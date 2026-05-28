import socket
import threading
import json
import random
import time
import queue
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
import base64

# Constants
SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345
MSS = 1000
BACKLOG = 5
CONNECTION_CLEANUP_INTERVAL = 10
TIMEOUT = 3  # Initial timeout value
IDLE_TIMEOUT = 10
HANDSHAKE_TIMEOUT = 5
MAX_SEQ = 2 ** 32 - 1  # Maximum 32-bit sequence number

FLAG_SYN = 'SYN'
FLAG_ACK = 'ACK'
FLAG_FIN = 'FIN'
FLAG_RST = 'RST'

def log_packet(context, direction, pkt):
    print(f"[{context}] {direction} packet:")
    print(f"  Source Port:        {pkt.src_port}")
    print(f"  Destination Port:   {pkt.dest_port}")
    print(f"  Sequence Number:    {pkt.seq}")
    print(f"  Acknowledgment Num: {pkt.ack}")
    print(f"  Flags:              {pkt.flags}")
    print(f"  Payload:            {pkt.payload if pkt.payload else '(empty)'}")
    print(f"  Receiver Window:    {pkt.recv_window}")

def seq_lt(a, b):
    """Check if sequence number a is less than b, considering wrap-around"""
    return ((a < b) and (b - a < MAX_SEQ // 2)) or ((a > b) and (a - b > MAX_SEQ // 2))

def seq_lte(a, b):
    """Check if sequence number a is less than or equal to b, considering wrap-around"""
    return a == b or seq_lt(a, b)

def seq_gt(a, b):
    """Check if sequence number a is greater than b, considering wrap-around"""
    return seq_lt(b, a)

def seq_gte(a, b):
    """Check if sequence number a is greater than or equal to b, considering wrap-around"""
    return a == b or seq_gt(a, b)

def seq_add(a, b):
    """Add two sequence numbers with wrap-around"""
    return (a + b) % (MAX_SEQ + 1)

def seq_sub(a, b):
    """Subtract sequence numbers with wrap-around"""
    return (a - b) % (MAX_SEQ + 1)


class EncryptionHelper:
    def __init__(self, key):
        """
        Initialize with a 32-byte AES key
        :param key: 32-byte encryption key (for AES-256)
        """
        if len(key) != 32:
                raise ValueError("AES key must be 32 bytes long")
        self.key = key

    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-CBC with PKCS7 padding
        :param plaintext: String to encrypt
        :return: base64-encoded string containing IV + ciphertext
        """
        # Generate a random 16-byte IV
        iv = get_random_bytes(16)

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Pad and encrypt
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        # Combine IV and ciphertext and base64 encode
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt(self, encrypted_data):
        """
        Decrypt encrypted data
        :param encrypted_data: base64-encoded string from encrypt()
        :return: Decrypted plaintext string
        """
        # Decode base64
        data = base64.b64decode(encrypted_data)

        # Extract IV (first 16 bytes) and ciphertext
        iv = data[:16]
        ciphertext = data[16:]

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # Decrypt and unpad
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode('utf-8')


class ECDHHelper:
    def __init__(self):
        # Generate ECC key pair using P-256 curve (NIST approved)
        self.private_key = ECC.generate(curve='p256')
        self.public_key = self.private_key.public_key()

    def get_public_key_bytes(self):
        """Serialize public key for transmission (compressed format)"""
        return self.public_key.export_key(format='DER', compress=True)

    def derive_shared_key(self, peer_public_key_bytes):
        """Derive 256-bit AES key from peer's public key"""
        try:
            peer_public_key = ECC.import_key(peer_public_key_bytes)
            # Calculate shared secret using ECDH
            shared_point = self.private_key.d * peer_public_key.pointQ
            # Use x-coordinate of the shared point as basis for key
            shared_secret = shared_point.x.to_bytes()
            # Hash to get fixed-length 32-byte key for AES-256
            return SHA256.new(shared_secret).digest()
        except ValueError as e:
            print(f"[ECDH] Error deriving key: {e}")
            raise


class Packet:
    def __init__(self, src_port, dest_port, seq, ack, flags, payload="", recv_window=0, encryptor=None,
                 ecdh_public_key=None):
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.encryptor = encryptor
        self.payload = payload  # Changed from _payload to payload
        self.recv_window = recv_window
        self.ecdh_public_key = ecdh_public_key

    def to_json(self):
        data = {
            'src_port': self.src_port,
            'dest_port': self.dest_port,
            'seq': self.seq,
            'ack': self.ack,
            'flags': self.flags,
            'payload': self.payload if self.payload else '',  # Changed from _payload to payload
            'recv_window': self.recv_window
        }
        if self.ecdh_public_key:
            data['ecdh_public_key'] = base64.b64encode(self.ecdh_public_key).decode()
        return json.dumps(data).encode()

    @staticmethod
    def from_json(data):
        d = json.loads(data.decode())
        ecdh_key = base64.b64decode(d['ecdh_public_key']) if 'ecdh_public_key' in d else None
        return Packet(
            src_port=d['src_port'],
            dest_port=d['dest_port'],
            seq=d['seq'],
            ack=d['ack'],
            flags=d['flags'],
            payload=d.get('payload', ''),
            recv_window=d.get('recv_window', 0),
            ecdh_public_key=ecdh_key
        )


class Connection:
    def __init__(self, addr, server, seq, ack):
        self.addr = addr
        self.server = server
        self.send_seq = seq % (MAX_SEQ + 1)
        self.recv_ack = ack % (MAX_SEQ + 1)
        self.expected_seq = ack % (MAX_SEQ + 1)
        self.recv_buffer = {}
        self.encryptor = None
        self.buffered_data = queue.Queue()
        self.running = True
        self.fin_received = False
        self.fin_sent = False
        self.fin_seq = None
        self.fin_sent_time = None
        self.data_available = threading.Event()
        self.last_active = time.time()
        self.last_ack_time = time.time()
        self.response_sent = threading.Event()  # Track if response has been sent

        # Flow control variables
        self.recv_buffer_size = 10 * MSS
        self.used_recv_buffer = 0
        self.zero_window_sent = False
        self.rwnd = self.recv_buffer_size

        # Congestion control variables
        self.cwnd = MSS  # Initial congestion window
        self.ssthresh = 64 * 1024  # Initial slow start threshold (64KB)

        # Adaptive RTO variables
        self.estimated_rtt = None  # Smoothed RTT (SRTT)
        self.dev_rtt = None  # RTT variation (DevRTT)
        self.rto = TIMEOUT  # Current RTO value

        # Send window management
        self.send_base = self.send_seq
        self.next_send_seq = self.send_seq
        self.sent_packets = {}  # Now stores dicts with packet info
        self.send_lock = threading.Lock()
        self.send_condition = threading.Condition()

        # Fast retransmit variables
        self.last_ack = self.send_base
        self.dup_ack_count = 0
        self.drop_counter = 1  # Number of packets to drop
        self.expected_drop_seq = 0  # Sequence number of the dropped packet
        self.dup_ack_count = 0
        threading.Thread(target=self._send_manager, daemon=True).start()
        threading.Thread(target=self._retransmit_watcher, daemon=True).start()

        print(f"[Server] New connection - Client: {addr}, Expected SEQ: {self.expected_seq}")

    def _update_rtt(self, sample_rtt):
        alpha = 0.125  # 1/8
        beta = 0.25  # 1/4

        if self.estimated_rtt is None:
            # First measurement
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            # Update estimates
            self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(sample_rtt - self.estimated_rtt)
            self.estimated_rtt = (1 - alpha) * self.estimated_rtt + alpha * sample_rtt

        # Calculate new RTO
        self.rto = self.estimated_rtt + 4 * max(self.dev_rtt, 0.01)  # Ensure positive

        # Enforce min/max bounds (RFC 6298)
        self.rto = max(1.0, min(self.rto, 60.0))
        print(f"[Server] Updated RTO: {self.rto:.3f}s (EstRTT: {self.estimated_rtt:.3f}s, DevRTT: {self.dev_rtt:.3f}s)")

    def send_data(self, data):
        # Encrypt data before sending
        if self.encryptor:
            data = self.encryptor.encrypt(data)

        with self.send_condition:
            segments = []
            i = 0
            while i < len(data):
                # Calculate available window as min(cwnd, rwnd)
                available_window = min(self.cwnd, self.rwnd)
                in_flight = self.next_send_seq - self.send_base

                if in_flight >= available_window:
                    time.sleep(0.01)
                    continue

                chunk = data[i:i + MSS]
                segments.append(chunk)
                i += len(chunk)

            for seg in segments:
                # Store packet info with initial values
                self.sent_packets[self.next_send_seq] = {
                    'pkt': None,  # Will be created when sent
                    'send_time': None,  # Set when actually transmitted
                    'payload': seg,
                    'retransmit_count': 0,  # Track retransmissions
                    'sampled': False  # For RTT measurement
                }
                self.next_send_seq += len(seg)
            self.send_condition.notify()

    def _send_manager(self):
        while self.running:
            with self.send_condition:
                # Calculate available window as min(cwnd, rwnd)
                available_window = min(self.cwnd, self.rwnd)

                while self.running and (
                        self.next_send_seq - self.send_base >= available_window or not self.sent_packets):
                    self.send_condition.wait(0.1)
                    available_window = min(self.cwnd, self.rwnd)

                if not self.running:
                    break

                for seq in list(self.sent_packets.keys()):
                    if seq < self.send_base + available_window:
                        pkt_info = self.sent_packets[seq]
                        if pkt_info['pkt'] is None:
                            # Create packet and send it
                            payload = pkt_info['payload']
                            available_recv_window = self.recv_buffer_size - self.used_recv_buffer
                            pkt = Packet(
                                SERVER_PORT, self.addr[1],
                                seq, self.expected_seq,
                                [FLAG_ACK],
                                payload,
                                recv_window=available_recv_window
                            )
                            # Update packet info with send time
                            self.sent_packets[seq] = {
                                'pkt': pkt,
                                'send_time': time.time(),
                                'payload': payload,
                                'retransmit_count': pkt_info['retransmit_count'],
                                'sampled': pkt_info['sampled']
                            }
                            self.server.sock.sendto(pkt.to_json(), self.addr)
                            self.last_active = time.time()
                            log_packet("Server", "Sent", pkt)

    def _retransmit_watcher(self):
        while self.running:
            time.sleep(0.5)
            now = time.time()
            with self.send_lock:
                if self.running and now - self.last_active > IDLE_TIMEOUT:
                    print(f"[Server] Idle timeout for {self.addr}, closing connection")
                    if not self.fin_sent:
                        fin_pkt = Packet(SERVER_PORT, self.addr[1], self.send_seq, self.expected_seq, [FLAG_FIN])
                        try:
                            self.server.sock.sendto(fin_pkt.to_json(), self.addr)
                            log_packet("Server", "Sent (idle timeout)", fin_pkt)
                            self.sent_packets[self.send_seq] = {
                                'pkt': fin_pkt,
                                'send_time': now,
                                'retransmit_count': 0,
                                'sampled': False
                            }
                            self.fin_sent = True
                            self.fin_sent_time = now
                            self.send_seq += 1
                        except Exception as e:
                            print(f"[Server] Error sending FIN: {e}")
                    self.running = False
                    break

                if self.fin_sent and now - self.fin_sent_time > self.rto * 3:
                    print(f"[Server] FIN-ACK timeout for {self.addr}")
                    self.running = False
                    break

                # Only check for timeout if there are outstanding packets
                if self.send_base < self.next_send_seq:
                    if now - self.last_ack_time >= self.rto:
                        self.cwnd = MSS
                        print(f"[Server] Timeout detected, reset cwnd to {self.cwnd}")

                # Modified packet iteration to handle dictionary values
                for seq, pkt_info in list(self.sent_packets.items()):
                    if pkt_info['pkt'] and pkt_info['send_time']:
                        elapsed = now - pkt_info['send_time']
                        if elapsed > self.rto:
                            if seq < self.send_base:
                                del self.sent_packets[seq]
                                continue

                            self.server.sock.sendto(pkt_info['pkt'].to_json(), self.addr)
                            pkt_info['send_time'] = now
                            pkt_info['retransmit_count'] += 1
                            print(f"[Server] Timeout, retransmitted seq {seq}")
                            log_packet("Server", "Resent", pkt_info['pkt'])

    def receive(self, timeout=5.0):
        if self.data_available.wait(timeout=timeout):
            result = ""
            while not self.buffered_data.empty():
                try:
                    payload = self.buffered_data.get_nowait()
                    result += payload
                    self.used_recv_buffer -= len(payload)
                except queue.Empty:
                    break
            self.data_available.clear()

            if self.zero_window_sent and self.used_recv_buffer < self.recv_buffer_size:
                available_window = self.recv_buffer_size - self.used_recv_buffer
                window_update = Packet(
                    SERVER_PORT, self.addr[1],
                    self.send_seq, self.expected_seq,
                    [FLAG_ACK],
                    recv_window=available_window
                )
                self.server.sock.sendto(window_update.to_json(), self.addr)
                self.zero_window_sent = False
                print(f"[Server] Sent window update: {available_window} bytes available")

            return result
        return ""

    def handle_packet(self, pkt):
        self.last_active = time.time()
        self.last_ack_time = time.time()
        ack_sent = False

        # Key exchange completed in handshake, no need for SYN processing here
        if hasattr(pkt, 'recv_window'):
            self.rwnd = pkt.recv_window

        if FLAG_FIN in pkt.flags:
            if not self.fin_sent:
                print(f"[Server] Received FIN from {self.addr}")
                self.fin_received = True
                self.expected_seq = seq_add(pkt.seq, 1)

                fin_ack_pkt = Packet(
                    SERVER_PORT, pkt.src_port,
                    self.send_seq, self.expected_seq,
                    [FLAG_ACK, FLAG_FIN]
                )

                with self.send_lock:
                    self.sent_packets[self.send_seq] = {
                        'pkt': fin_ack_pkt,
                        'send_time': time.time(),
                        'payload': "",
                        'retransmit_count': 0,
                        'sampled': False
                    }

                self.server.sock.sendto(fin_ack_pkt.to_json(), self.addr)
                self.last_active = time.time()
                log_packet("Server", "Sent (FIN-ACK)", fin_ack_pkt)
                ack_sent = True

                self.fin_sent = True
                self.fin_seq = self.send_seq
                self.fin_sent_time = time.time()
                self.send_seq = seq_add(self.send_seq, 1)
            else:
                now = time.time()
                with self.send_lock:
                    if self.fin_seq in self.sent_packets:
                        pkt_info = self.sent_packets[self.fin_seq]
                        if pkt_info['pkt']:
                            self.server.sock.sendto(pkt_info['pkt'].to_json(), self.addr)
                            pkt_info['send_time'] = now
                            self.sent_packets[self.fin_seq] = pkt_info
                            self.last_active = now
                            log_packet("Server", "Resent (FIN-ACK)", pkt_info['pkt'])

        if FLAG_ACK in pkt.flags and self.fin_sent:
            if pkt.ack > self.fin_seq:
                print(f"[Server] FIN-ACK acknowledged by {self.addr}")
                if self.response_sent.wait(timeout=10.0):
                    self.running = False
                else:
                    print(f"[Server] Closing connection without sending response")
                    self.running = False

        if FLAG_RST in pkt.flags:
            print(f"[Server] Received RST from {self.addr} — closing.")
            self.running = False
            return

        if pkt.payload:
            #####################################################
            # START OF PACKET DROP SIMULATION (REPLACE WITH THIS)
            #####################################################
            # Case 1: This is the packet we should drop
            if (self.drop_counter > 0 and
                    pkt.seq == self.expected_seq and
                    not self.expected_drop_seq):
                print(f"[Server] Simulating drop of packet (seq={pkt.seq})")
                self.drop_counter -= 1
                self.expected_drop_seq = pkt.seq
                return  # Skip processing this packet

            # Case 2: This is the retransmitted packet we've been waiting for
            if pkt.seq == self.expected_drop_seq:
                print(f"[Server] Processing retransmitted packet (seq={pkt.seq})")
                self.expected_drop_seq = 0  # Reset drop target
                self.dup_ack_count = 0  # Reset duplicate counter
                # Continue to normal processing below

            # Case 3: Send duplicate ACK for dropped packet
            elif self.expected_drop_seq and self.dup_ack_count < 3:
                print(f"[Server] Sending duplicate ACK #{self.dup_ack_count + 1} for seq={self.expected_drop_seq}")
                ack_pkt = Packet(
                    SERVER_PORT, pkt.src_port,
                    self.send_seq, self.expected_drop_seq,
                    [FLAG_ACK],
                    recv_window=self.recv_buffer_size - self.used_recv_buffer
                )
                self.server.sock.sendto(ack_pkt.to_json(), self.addr)
                self.dup_ack_count += 1
                log_packet("Server", "Sent (duplicate)", ack_pkt)
                return  # Skip normal processing
            #####################################################
            # END OF PACKET DROP SIMULATION
            #####################################################
            payload_len = len(pkt.payload)

            if self.used_recv_buffer + payload_len > self.recv_buffer_size:
                print(f"[Server] Discarding packet, buffer full: {payload_len} bytes")
                ack_pkt = Packet(
                    SERVER_PORT, pkt.src_port,
                    self.send_seq, self.expected_seq,
                    [FLAG_ACK],
                    recv_window=0
                )
                self.server.sock.sendto(ack_pkt.to_json(), self.addr)
                self.zero_window_sent = True
                return

            self.recv_buffer[pkt.seq] = pkt.payload
            self.used_recv_buffer += payload_len

            processed = False
            while self.expected_seq in self.recv_buffer:
                payload = self.recv_buffer.pop(self.expected_seq)
                self.buffered_data.put(payload)
                self.expected_seq = seq_add(self.expected_seq, len(payload))
                processed = True

            if processed:
                self.data_available.set()

        available_window = self.recv_buffer_size - self.used_recv_buffer

        # Only send ACK if:
        # 1. Packet has payload (data), OR
        # 2. Packet has FIN/RST flag, OR
        # 3. We need to update the window (zero_window_sent)
        if (pkt.payload or FLAG_FIN in pkt.flags or FLAG_RST in pkt.flags or self.zero_window_sent) and not ack_sent:
            ack_pkt = Packet(
                SERVER_PORT, pkt.src_port,
                self.send_seq, self.expected_seq,
                [FLAG_ACK],
                recv_window=available_window
            )
            self.server.sock.sendto(ack_pkt.to_json(), self.addr)
            self.last_active = time.time()
            log_packet("Server", "Sent", ack_pkt)

        self.zero_window_sent = (available_window == 0)

        if FLAG_ACK in pkt.flags:
            ack_num = pkt.ack
            with self.send_lock:
                if ack_num == self.last_ack:
                    self.dup_ack_count += 1
                    if self.dup_ack_count == 3:
                        # Triple duplicate ACK - halve congestion window
                        self.cwnd = max(MSS, self.cwnd // 2)
                        print(f"[Server] Triple duplicate ACK, cwnd halved to {self.cwnd}")

                        if self.send_base in self.sent_packets:
                            pkt_info = self.sent_packets[self.send_base]
                            if pkt_info['pkt']:
                                pkt_to_retransmit = pkt_info['pkt']
                                self.server.sock.sendto(pkt_to_retransmit.to_json(), self.addr)
                                self.last_active = time.time()
                                print(f"[Server] Fast retransmit seq {self.send_base}")
                                log_packet("Server", "Fast Retransmit", pkt_to_retransmit)
                                self.dup_ack_count = 0
                elif ack_num > self.last_ack:
                    # New valid ACK - additive increase
                    self.cwnd += MSS
                    print(f"[Server] New ACK received, cwnd increased to {self.cwnd}")

                    self.last_ack = ack_num
                    self.dup_ack_count = 0

                    # Process RTT samples
                    keys = list(self.sent_packets.keys())
                    for seq in keys:
                        if seq < ack_num and seq in self.sent_packets:
                            pkt_info = self.sent_packets[seq]
                            # Only use first transmission for RTT measurement
                            if (pkt_info['retransmit_count'] == 0
                                    and not pkt_info['sampled']):
                                sample_rtt = time.time() - pkt_info['send_time']
                                self._update_rtt(sample_rtt)
                                pkt_info['sampled'] = True
                                self.sent_packets[seq] = pkt_info

                if ack_num > self.send_base:
                    keys = list(self.sent_packets.keys())
                    for seq in keys:
                        if seq < ack_num:
                            del self.sent_packets[seq]
                    self.send_base = ack_num
                    with self.send_condition:
                        self.send_condition.notify()

    def abort(self):
        if not self.running:
            return

        print(f"[Server] Aborting connection to {self.addr} with RST")

        rst_pkt = Packet(SERVER_PORT, self.addr[1], self.send_seq, 0, [FLAG_RST])
        try:
            self.server.sock.sendto(rst_pkt.to_json(), self.addr)
            log_packet("Server", "Sent", rst_pkt)
        except OSError as e:
            print(f"[Server] Error sending RST: {str(e)}")

        self.running = False
        print(f"[Server] Connection to {self.addr} aborted")


class TcpOverUdpServer:
    def __init__(self, ip=SERVER_IP, port=SERVER_PORT, backlog=BACKLOG):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.sock.settimeout(0.5)
        self.backlog = backlog
        self.accept_queue = queue.Queue(maxsize=backlog)
        self.connections = {}
        self.pending_handshakes = {}
        self.running = True
        print(f"[Server] Listening on {ip}:{port}")
        threading.Thread(target=self._listen_loop, daemon=True).start()
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def _cleanup_loop(self):
        while self.running:
            time.sleep(CONNECTION_CLEANUP_INTERVAL)
            now = time.time()

            to_remove = []
            for addr, conn in list(self.connections.items()):
                if not conn.running:
                    to_remove.append(addr)
            for addr in to_remove:
                del self.connections[addr]
                print(f"[Server] Cleaned up connection: {addr}")

            to_remove_handshakes = []
            for addr, (syn_ack, ecdh, client_key, timestamp) in list(self.pending_handshakes.items()):
                if now - timestamp > TIMEOUT * 3:
                    to_remove_handshakes.append(addr)
            for addr in to_remove_handshakes:
                del self.pending_handshakes[addr]
                print(f"[Server] Cleaned up pending handshake: {addr}")

    def _listen_loop(self):
        while self.running:
            try:
                data, udp_addr = self.sock.recvfrom(4096)
                pkt = Packet.from_json(data)
                client_addr = (udp_addr[0], pkt.src_port)

                log_packet("Server", "Received", pkt)

                if FLAG_RST in pkt.flags:
                    if client_addr in self.connections:
                        conn = self.connections[client_addr]
                        if conn and conn.running:
                            print(f"[Server] Received RST for {client_addr}, aborting connection")
                            conn.running = False
                    continue

                if client_addr in self.connections:
                    conn = self.connections.get(client_addr)
                    if conn and conn.running:
                        conn.handle_packet(pkt)
                    else:
                        rst_pkt = Packet(SERVER_PORT, pkt.src_port, 0, 0, [FLAG_RST])
                        self.sock.sendto(rst_pkt.to_json(), (udp_addr[0], pkt.src_port))
                        log_packet("Server", "Sent RST", rst_pkt)

                elif client_addr in self.pending_handshakes:
                    syn_ack, ecdh, client_key, timestamp = self.pending_handshakes[client_addr]

                    if FLAG_SYN in pkt.flags:
                        self.sock.sendto(syn_ack.to_json(), (udp_addr[0], pkt.src_port))
                        log_packet("Server", "Resent", syn_ack)
                        print(f"[Server] Resent SYN-ACK to {client_addr}")
                        self.pending_handshakes[client_addr] = (syn_ack, ecdh, client_key, time.time())

                    elif FLAG_ACK in pkt.flags:
                        if pkt.ack == syn_ack.seq + 1:
                            try:
                                # Derive shared key from client's public key
                                aes_key = ecdh.derive_shared_key(client_key)
                                encryptor = EncryptionHelper(aes_key)

                                conn = Connection(client_addr, self, syn_ack.seq + 1, pkt.seq)
                                conn.encryptor = encryptor  # Set encryptor for connection

                                self.connections[client_addr] = conn
                                self.accept_queue.put((conn, client_addr))
                                del self.pending_handshakes[client_addr]
                                print(f"[Server] Connection established with {client_addr}")
                            except Exception as e:
                                print(f"[Server] Key derivation failed: {e}")
                                rst_pkt = Packet(SERVER_PORT, pkt.src_port, 0, 0, [FLAG_RST])
                                self.sock.sendto(rst_pkt.to_json(), (udp_addr[0], pkt.src_port))
                                log_packet("Server", "Sent RST", rst_pkt)
                        else:
                            print(f"[Server] Invalid ACK from {client_addr}")
                            rst_pkt = Packet(SERVER_PORT, pkt.src_port, 0, 0, [FLAG_RST])
                            self.sock.sendto(rst_pkt.to_json(), (udp_addr[0], pkt.src_port))
                            log_packet("Server", "Sent RST", rst_pkt)


                # Inside the else block for handling SYN packets:

                else:

                    if FLAG_SYN in pkt.flags:
                        # Create ECDH object for this handshake
                        ecdh = ECDHHelper()
                        start_time = time.time()
                        seq = random.randint(10000, 50000)

                        ack = pkt.seq + 1

                        # Include server's public key in SYN-ACK

                        syn_ack = Packet(

                            SERVER_PORT, pkt.src_port,

                            seq, ack,

                            [FLAG_SYN, FLAG_ACK],

                            recv_window=10 * MSS,

                            ecdh_public_key=ecdh.get_public_key_bytes()

                        )

                        self.sock.sendto(syn_ack.to_json(), (udp_addr[0], pkt.src_port))

                        log_packet("Server", "Sent", syn_ack)

                        print(f"[Server] Sent SYN-ACK to {udp_addr[0]}:{pkt.src_port}")

                        # Store handshake state

                        self.pending_handshakes[client_addr] = (syn_ack, ecdh, pkt.ecdh_public_key, time.time())

                    else:
                        rst_pkt = Packet(SERVER_PORT, pkt.src_port, 0, 0, [FLAG_RST])
                        self.sock.sendto(rst_pkt.to_json(), (udp_addr[0], pkt.src_port))
                        log_packet("Server", "Sent RST", rst_pkt)

            except socket.timeout:
                continue
            except json.JSONDecodeError:
                print(f"[Server] Invalid packet from {udp_addr}")
            except Exception as e:
                print(f"[Server] Error: {str(e)}")

    def accept(self):
        return self.accept_queue.get()

    def close(self):
        self.running = False
        self.sock.close()


if __name__ == '__main__':
    server = TcpOverUdpServer()

    try:
        while True:
            conn, addr = server.accept()
            print(f"\n[SERVER] Accepted connection from {addr}")


            def handle_connection(conn, addr):
                try:
                    # Test receiving encrypted data
                    encrypted_data = conn.receive(timeout=5.0)
                    if encrypted_data:
                        try:
                            decrypted = conn.encryptor.decrypt(encrypted_data)
                            print(f"[SERVER] Received from {addr}: {decrypted}")

                            # Send encrypted response
                            response = f"Server received your : '{decrypted}'"
                            conn.send_data(response)
                            print(f"[SERVER] Sent response to {addr}")
                            conn.response_sent.set()

                        except Exception as e:
                            print(f"[SERVER] Decryption failed: {e}")
                            conn.abort()
                    else:
                        print(f"[SERVER] No data from {addr} within timeout")

                    # Wait for client to initiate closure
                    print(f"[SERVER] Waiting for client closure from {addr}...")
                    start_time = time.time()
                    while time.time() - start_time < 15.0:  # Wait up to 15 seconds
                        if conn.fin_received:
                            print(f"[SERVER] Client {addr} initiated closure")
                            break
                        time.sleep(0.1)

                    # If client hasn't closed, send FIN (fallback)
                    if not conn.fin_received:
                        print(f"[SERVER] Client {addr} didn't close, initiating closure")
                        fin_pkt = Packet(
                            SERVER_PORT, addr[1],
                            conn.send_seq, conn.expected_seq,
                            [FLAG_FIN]
                        )
                        conn.server.sock.sendto(fin_pkt.to_json(), addr)
                        conn.fin_sent = True
                        conn.fin_seq = conn.send_seq
                        conn.fin_sent_time = time.time()
                        conn.send_seq += 1
                        print(f"[SERVER] Sent FIN to {addr}")

                    # Wait for final ACK
                    start_time = time.time()
                    while time.time() - start_time < conn.rto * 2:
                        if not conn.running:
                            break
                        time.sleep(0.1)

                except Exception as e:
                    print(f"[SERVER] Connection handler error for {addr}: {e}")
                finally:
                    # Clean up connection
                    conn.running = False
                    print(f"[SERVER] Connection closed for {addr}")


            # Start thread for each connection
            threading.Thread(
                target=handle_connection,
                args=(conn, addr),
                daemon=True
            ).start()

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down gracefully...")
    finally:
        server.close()