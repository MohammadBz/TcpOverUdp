import socket
import json
import random
import time
import threading
import queue
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
import base64

SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345
MSS = 1000
TIMEOUT = 3  # Initial timeout value
WINDOW_SIZE = 3 * MSS
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


class TcpOverUdpClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.src_port = random.randint(1025, 65535)
        self.sock.bind(('0.0.0.0', self.src_port))
        self.sock.settimeout(0.5)
        self.server_addr = (SERVER_IP, SERVER_PORT)
        self.seq = random.randint(1, MAX_SEQ)
        self.ack = 0
        self.ecdh = ECDHHelper()
        self.encryptor = None
        self.send_base = self.seq
        self.next_seq = self.seq
        self.connected = False
        self.sent_packets = {}  # Store packet info dictionaries
        self.lock = threading.Lock()
        self.running = False
        self.fin_sent = False
        self.fin_sent_time = None
        self.last_active = time.time()
        self.last_ack = 0
        self.dup_ack_count = 0
        self.expected_seq = 0
        self.recv_buffer = {}
        self.buffered_data = queue.Queue()
        self.data_available = threading.Event()

        # Flow control variables
        self.recv_buffer_size = 10 * MSS
        self.used_recv_buffer = 0
        self.zero_window_sent = False
        self.rwnd = self.recv_buffer_size  # Initialize with actual window size

        # Congestion control variables
        self.cwnd = MSS  # Initial congestion window
        self.ssthresh = 64 * 1024  # Initial slow start threshold (64KB)

        # Adaptive RTO variables
        self.estimated_rtt = None  # Smoothed RTT (SRTT)
        self.dev_rtt = None  # RTT variation (DevRTT)
        self.rto = TIMEOUT  # Current RTO value

    def connect(self):
        max_retries = 3
        retry_count = 0
        start_time = time.time()

        # Include ECDH public key in SYN packet
        syn_pkt = Packet(
            self.src_port, SERVER_PORT,
            self.seq, 0, [FLAG_SYN],
            recv_window=self.recv_buffer_size,
            ecdh_public_key=self.ecdh.get_public_key_bytes()
        )

        while retry_count < max_retries and time.time() - start_time < HANDSHAKE_TIMEOUT:
            try:
                self.sock.sendto(syn_pkt.to_json(), self.server_addr)
                log_packet("CLIENT", "Sent", syn_pkt)
                self.last_active = time.time()

                self.sock.settimeout(self.rto)
                data, addr = self.sock.recvfrom(4096)
                self.last_active = time.time()

                if addr[0] != SERVER_IP or addr[1] != SERVER_PORT:
                    continue

                syn_ack = Packet.from_json(data)
                log_packet("CLIENT", "Received", syn_ack)

                if FLAG_SYN in syn_ack.flags and FLAG_ACK in syn_ack.flags:
                    if syn_ack.ack != self.seq + 1:
                        print(f"[CLIENT] Invalid SYN-ACK ACK number: expected {self.seq + 1}, got {syn_ack.ack}")
                        continue

                    if hasattr(syn_ack, 'ecdh_public_key'):
                        try:
                            aes_key = self.ecdh.derive_shared_key(syn_ack.ecdh_public_key)
                            self.encryptor = EncryptionHelper(aes_key)
                        except Exception as e:
                            print(f"[Client] ECDH failed: {e}")
                            raise ConnectionError("Key exchange failed")
                    else:
                        print(f"[CLIENT] No public key in SYN-ACK")
                        continue

                    self.ack = syn_ack.seq + 1
                    self.expected_seq = syn_ack.seq + 1
                    self.seq += 1
                    self.send_base = self.seq
                    self.next_seq = self.seq

                    ack_pkt = Packet(
                        self.src_port, SERVER_PORT,
                        self.seq, self.ack, [FLAG_ACK],
                        recv_window=self.recv_buffer_size
                    )
                    self.sock.sendto(ack_pkt.to_json(), self.server_addr)
                    log_packet("CLIENT", "Sent", ack_pkt)
                    self.last_active = time.time()

                    self.running = True
                    threading.Thread(target=self._ack_listener, daemon=True).start()
                    threading.Thread(target=self._retransmit_watcher, daemon=True).start()

                    self.connected = True
                    self.sock.settimeout(0.5)
                    print("[CLIENT] Connection established with encryption")
                    return
            except socket.timeout:
                retry_count += 1
                print(f"[CLIENT] Connection attempt {retry_count}/{max_retries} timed out")
            except ConnectionResetError as e:
                print(f"[CLIENT] Connection reset: {str(e)}")
                retry_count += 1
                time.sleep(0.5)
            except OSError as e:
                if e.winerror == 10054:
                    print(f"[CLIENT] Connection reset: {str(e)}")
                    retry_count += 1
                    time.sleep(0.5)
                else:
                    print(f"[CLIENT] Connection error: {str(e)}")
                    break
            except Exception as e:
                print(f"[CLIENT] Connection error: {str(e)}")
                break

        self.sock.settimeout(0.5)
        print("[CLIENT] Failed to connect: Server unavailable or not responding")
        self.running = False
        self.sock.close()
        raise ConnectionError("Server unavailable or not responding")

    def send(self, data):
        if not self.connected or not self.running:
            return

        # Encrypt data before sending
        if not self.encryptor:
            raise Exception("Encryption not set up")
        data = self.encryptor.encrypt(data)

        i = 0
        while i < len(data):
            with self.lock:
                # Calculate available window as min(cwnd, rwnd)
                available_window = min(self.cwnd, self.rwnd)
                in_flight = self.next_seq - self.send_base

                if in_flight >= available_window:
                    time.sleep(0.01)
                    continue

                chunk = data[i:i + MSS]
                available_recv_window = self.recv_buffer_size - self.used_recv_buffer
                pkt = Packet(
                    self.src_port, SERVER_PORT,
                    self.next_seq, self.ack, [FLAG_ACK],
                    chunk,
                    recv_window=available_recv_window
                )
                self.sock.sendto(pkt.to_json(), self.server_addr)
                log_packet("CLIENT", "Sent", pkt)
                self.last_active = time.time()

                # Store packet info with send time
                self.sent_packets[self.next_seq] = {
                    'pkt': pkt,
                    'send_time': time.time(),
                    'retransmit_count': 0,
                    'sampled': False  # For RTT measurement
                }
                self.next_seq += len(chunk)
                i += len(chunk)

    def _ack_listener(self):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(4096)
                self.last_active = time.time()
                pkt = Packet.from_json(data)
                log_packet("CLIENT", "Received", pkt)

                if hasattr(pkt, 'recv_window'):
                    self.rwnd = pkt.recv_window

                if FLAG_RST in pkt.flags:
                    print("[CLIENT] Received RST, aborting connection")
                    self.running = False
                    break

                if FLAG_FIN in pkt.flags:
                    if not self.fin_sent:
                        print("[CLIENT] Received FIN from server")
                        # Send ACK for FIN immediately
                        ack_pkt = Packet(
                            self.src_port, SERVER_PORT,
                            self.next_seq, pkt.seq + 1,
                            [FLAG_ACK]
                        )
                        self.sock.sendto(ack_pkt.to_json(), self.server_addr)
                        log_packet("CLIENT", "Sent (FIN-ACK)", ack_pkt)
                        self.last_active = time.time()

                        # Update expected sequence
                        self.expected_seq = pkt.seq + 1

                        # Don't send FIN here - let close() handle it
                    else:
                        print("[CLIENT] Received FIN from server (after FIN sent)")
                        # Send ACK for FIN
                        ack_pkt = Packet(
                            self.src_port, SERVER_PORT,
                            self.next_seq, pkt.seq + 1,
                            [FLAG_ACK]
                        )
                        self.sock.sendto(ack_pkt.to_json(), self.server_addr)
                        log_packet("CLIENT", "Sent (ACK for FIN)", ack_pkt)
                        self.last_active = time.time()

                if pkt.payload:
                    payload_len = len(pkt.payload)

                    # Check buffer space
                    if self.used_recv_buffer + payload_len > self.recv_buffer_size:
                        print(f"[CLIENT] Discarding packet, buffer full: {payload_len} bytes")
                        ack_pkt = Packet(
                            self.src_port, SERVER_PORT,
                            self.next_seq, self.expected_seq,
                            [FLAG_ACK],
                            recv_window=0
                        )
                        self.sock.sendto(ack_pkt.to_json(), self.server_addr)
                        log_packet("CLIENT", "Sent", ack_pkt)
                        self.zero_window_sent = True
                        continue

                    with self.lock:
                        if seq_lt(pkt.seq, self.expected_seq):
                            # Duplicate packet - acknowledge again
                            ack_pkt = Packet(
                                self.src_port, SERVER_PORT,
                                self.next_seq, self.expected_seq,
                                [FLAG_ACK],
                                recv_window=self.recv_buffer_size - self.used_recv_buffer
                            )
                            self.sock.sendto(ack_pkt.to_json(), self.server_addr)
                            log_packet("CLIENT", "Sent", ack_pkt)
                        elif pkt.seq == self.expected_seq:
                            # In-order packet
                            self.buffered_data.put(pkt.payload)
                            self.expected_seq = seq_add(self.expected_seq, len(pkt.payload))
                            self.used_recv_buffer += payload_len

                            # Process any buffered packets
                            while self.expected_seq in self.recv_buffer:
                                payload = self.recv_buffer.pop(self.expected_seq)
                                self.buffered_data.put(payload)
                                self.expected_seq = seq_add(self.expected_seq, len(payload))
                                self.used_recv_buffer += len(payload)

                            # Send ACK with updated window
                            ack_pkt = Packet(
                                self.src_port, SERVER_PORT,
                                self.next_seq, self.expected_seq,
                                [FLAG_ACK],
                                recv_window=self.recv_buffer_size - self.used_recv_buffer
                            )
                            self.sock.sendto(ack_pkt.to_json(), self.server_addr)
                            log_packet("CLIENT", "Sent", ack_pkt)
                        else:
                            # Out-of-order packet
                            self.recv_buffer[pkt.seq] = pkt.payload
                            self.used_recv_buffer += payload_len

                            # Acknowledge last in-order byte
                            ack_pkt = Packet(
                                self.src_port, SERVER_PORT,
                                self.next_seq, self.expected_seq,
                                [FLAG_ACK],
                                recv_window=self.recv_buffer_size - self.used_recv_buffer
                            )
                            self.sock.sendto(ack_pkt.to_json(), self.server_addr)
                            log_packet("CLIENT", "Sent", ack_pkt)

                    # Update zero window state
                    available_window = self.recv_buffer_size - self.used_recv_buffer
                    self.zero_window_sent = (available_window == 0)

                if FLAG_ACK in pkt.flags:
                    with self.lock:
                        if pkt.ack == self.last_ack:
                            self.dup_ack_count += 1
                            if self.dup_ack_count == 3:
                                # Triple duplicate ACK - halve congestion window
                                self.cwnd = max(MSS, self.cwnd // 2)
                                print(f"[CLIENT] Triple duplicate ACK, cwnd halved to {self.cwnd}")

                                if self.send_base in self.sent_packets:
                                    pkt_info = self.sent_packets[self.send_base]
                                    self.sock.sendto(pkt_info['pkt'].to_json(), self.server_addr)
                                    print(f"[CLIENT] Fast retransmit seq {self.send_base}")
                                    log_packet("CLIENT", "Fast Retransmit", pkt_info['pkt'])
                                    self.dup_ack_count = 0
                        elif pkt.ack > self.last_ack:
                            # New valid ACK - additive increase
                            self.cwnd += MSS
                            print(f"[CLIENT] New ACK received, cwnd increased to {self.cwnd}")

                            self.last_ack = pkt.ack
                            self.dup_ack_count = 0

                        acked_seq = pkt.ack
                        keys = list(self.sent_packets.keys())
                        for seq in keys:
                            if seq < acked_seq and seq in self.sent_packets:
                                pkt_info = self.sent_packets[seq]
                                # Only use first transmission for RTT
                                if (pkt_info['retransmit_count'] == 0
                                        and not pkt_info['sampled']):
                                    sample_rtt = time.time() - pkt_info['send_time']
                                    self._update_rtt(sample_rtt)
                                    pkt_info['sampled'] = True

                                # Remove ACKed packets
                                del self.sent_packets[seq]

                        self.send_base = acked_seq

            except socket.timeout:
                continue
            except ConnectionResetError as e:
                print(f"[CLIENT] Connection reset in listener: {str(e)}")
                if not self.connected:
                    continue
                self.running = False
                break
            except OSError as e:
                if e.winerror == 10054:
                    print(f"[CLIENT] Connection reset in listener: {str(e)}")
                    if not self.connected:
                        continue
                    self.running = False
                    break
                else:
                    print(f"[CLIENT] Socket error in listener: {str(e)}")
                    self.running = False
                    break
            except Exception as e:
                print(f"[CLIENT] Unexpected error in listener: {str(e)}")
                self.running = False
                break

    def _update_rtt(self, sample_rtt):
        alpha = 0.125  # 1/8
        beta = 0.25  # 1/4

        # Apply minimum RTT threshold (1ms) for realistic networks
        sample_rtt = max(sample_rtt, 0.001)

        if self.estimated_rtt is None:
            # First measurement
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            # Update estimates
            self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(sample_rtt - self.estimated_rtt)
            self.estimated_rtt = (1 - alpha) * self.estimated_rtt + alpha * sample_rtt

        # Calculate new RTO with minimum bound
        self.rto = max(1.0, self.estimated_rtt + 4 * self.dev_rtt)
        print(f"[CLIENT] Updated RTO: {self.rto:.3f}s (EstRTT: {self.estimated_rtt:.3f}s, DevRTT: {self.dev_rtt:.3f}s)")

    def _retransmit_watcher(self):
        while self.running:
            time.sleep(0.1)
            now = time.time()
            with self.lock:
                if self.connected and now - self.last_active > IDLE_TIMEOUT:
                    print("[CLIENT] Idle timeout, closing connection")
                    if not self.fin_sent:
                        fin_pkt = Packet(self.src_port, SERVER_PORT, self.next_seq, self.ack, [FLAG_FIN])
                        try:
                            self.sock.sendto(fin_pkt.to_json(), self.server_addr)
                            log_packet("CLIENT", "Sent (idle timeout)", fin_pkt)
                            self.sent_packets[self.next_seq] = {
                                'pkt': fin_pkt,
                                'send_time': time.time(),
                                'retransmit_count': 0,
                                'sampled': False
                            }
                            self.fin_sent = True
                            self.fin_sent_time = time.time()
                            self.next_seq += 1
                        except OSError as e:
                            print(f"[CLIENT] Error sending FIN: {str(e)}")
                    self.running = False
                    break

                if self.fin_sent and self.sent_packets and now - self.fin_sent_time > self.rto * 3:
                    print("[CLIENT] FIN not acknowledged, closing")
                    self.running = False
                    break

                # Only check for timeouts if we have packets in flight
                if self.send_base < self.next_seq:
                    timeout_occurred = False
                    keys = list(self.sent_packets.keys())
                    for seq in keys:
                        if seq not in self.sent_packets:
                            continue
                        pkt_info = self.sent_packets[seq]
                        elapsed = now - pkt_info['send_time']
                        if elapsed > self.rto:
                            if not timeout_occurred:
                                self.cwnd = MSS
                                print(f"[CLIENT] Timeout detected with packets in flight, reset cwnd to {self.cwnd}")
                                timeout_occurred = True

                            try:
                                self.sock.sendto(pkt_info['pkt'].to_json(), self.server_addr)
                                pkt_info['send_time'] = now
                                pkt_info['retransmit_count'] += 1
                                print(f"[CLIENT] Retransmitted seq {seq} (attempt {pkt_info['retransmit_count']})")
                                log_packet("CLIENT", "Resent", pkt_info['pkt'])
                            except OSError as e:
                                print(f"[CLIENT] Error retransmitting: {str(e)}")

    def receive(self, size, timeout=5.0):
        if not self.connected or not self.running:
            return ""

        start = time.time()
        result = ""
        while len(result) < size and time.time() - start < timeout:
            try:
                payload = self.buffered_data.get(timeout=0.5)
                result += payload

                # Free up buffer space
                with self.lock:
                    self.used_recv_buffer -= len(payload)

                # If buffer was full, send window update
                if self.zero_window_sent and self.used_recv_buffer < self.recv_buffer_size:
                    available_window = self.recv_buffer_size - self.used_recv_buffer
                    window_update = Packet(
                        self.src_port, SERVER_PORT,
                        self.next_seq, self.expected_seq,
                        [FLAG_ACK],
                        recv_window=available_window
                    )
                    self.sock.sendto(window_update.to_json(), self.server_addr)
                    self.zero_window_sent = False
                    print(f"[CLIENT] Sent window update: {available_window} bytes available")

            except queue.Empty:
                if not self.running:
                    break
        return result

    def close(self):
        if not self.connected or not self.running:
            return

        print("[CLIENT] Starting graceful closure")

        # Send FIN if not already sent
        if not self.fin_sent:
            fin_pkt = Packet(
                self.src_port, SERVER_PORT,
                self.next_seq, self.ack,
                [FLAG_FIN]
            )
            try:
                self.sock.sendto(fin_pkt.to_json(), self.server_addr)
                log_packet("CLIENT", "Sent FIN", fin_pkt)
                with self.lock:
                    self.sent_packets[self.next_seq] = {
                        'pkt': fin_pkt,
                        'send_time': time.time(),
                        'retransmit_count': 0,
                        'sampled': False
                    }
                self.fin_sent = True
                self.fin_sent_time = time.time()
                self.next_seq += 1
            except OSError as e:
                print(f"[CLIENT] Error sending FIN: {str(e)}")

        # Wait for server's FIN and send ACK
        start_time = time.time()
        while time.time() - start_time < self.rto * 3:
            try:
                self.sock.settimeout(0.5)
                data, _ = self.sock.recvfrom(4096)
                pkt = Packet.from_json(data)
                log_packet("CLIENT", "Received", pkt)

                if FLAG_FIN in pkt.flags:
                    print("[CLIENT] Received FIN from server during closure")
                    ack_pkt = Packet(
                        self.src_port, SERVER_PORT,
                        self.next_seq, pkt.seq + 1,
                        [FLAG_ACK]
                    )
                    self.sock.sendto(ack_pkt.to_json(), self.server_addr)
                    log_packet("CLIENT", "Sent FIN-ACK", ack_pkt)
                    break

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[CLIENT] Error during closure: {str(e)}")
                break

        # Now stop threads and close socket
        self.running = False
        time.sleep(0.2)  # Let threads exit

        try:
            self.sock.close()
        except OSError as e:
            print(f"[CLIENT] Socket close error: {str(e)}")

        self.connected = False
        print("[CLIENT] Connection closed gracefully")

    def abort(self):
        if not self.connected or not self.running:
            return

        print("[CLIENT] Aborting connection with RST")

        rst_pkt = Packet(self.src_port, SERVER_PORT, self.next_seq, self.ack, [FLAG_RST])
        try:
            self.sock.sendto(rst_pkt.to_json(), self.server_addr)
            log_packet("CLIENT", "Sent", rst_pkt)
        except OSError as e:
            print(f"[CLIENT] Error sending RST: {str(e)}")

        self.running = False
        try:
            self.sock.close()
        except:
            pass
        print("[CLIENT] Connection aborted")


if __name__ == '__main__':
    client = TcpOverUdpClient()
    try:
        client.connect()
        if client.connected:
            # Encrypt and send message
            message = "Hello server!"
            client.send(message)
            print(f"[CLIENT] Sent encrypted message: {message}")

            print("[CLIENT] Waiting for server response...")
            # Receive encrypted response
            encrypted_response = client.receive(1024, timeout=5)

            # Decrypt response
            if encrypted_response and client.encryptor:
                decrypted = client.encryptor.decrypt(encrypted_response)
                print(f"[CLIENT] Received decrypted response: {decrypted}")
            else:
                print("[CLIENT] No response received or encryption not set up")

            print("[CLIENT] Closing connection")
            client.close()
    except ConnectionError as e:
        print(f"[CLIENT] Connection failed: {str(e)}")
    except Exception as e:
        print(f"[CLIENT] Unexpected error: {str(e)}")