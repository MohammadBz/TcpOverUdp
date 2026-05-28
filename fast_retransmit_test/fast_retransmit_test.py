

import time
import threading
from clientV3 import TcpOverUdpClient
MSS = 1000


def client_operation(client_id):
    try:
        print(f"\n--- Client {client_id} starting ---")
        client = TcpOverUdpClient()

        # Connect to server
        client.connect()
        print(f"Client {client_id} connected")

        # Create large message (4 segments)
        large_message = "A" * (4 * MSS)  # Exactly 4000 bytes
        print(f"Client {client_id} sending {len(large_message)} bytes message")
        client.send(large_message)

        # Monitor for fast retransmit
        fast_retransmit_occurred = False
        start_time = time.time()
        while time.time() - start_time < 10:
            if hasattr(client, 'fast_retransmit_triggered'):
                fast_retransmit_occurred = True
                print(f"Client {client_id} triggered fast retransmit!")
                break
            time.sleep(0.1)

        if not fast_retransmit_occurred:
            print(f"Client {client_id} did not trigger fast retransmit")

        # Close connection
        print(f"Client {client_id} closing...")
        client.close()
        print(f"--- Client {client_id} finished ---")

    except Exception as e:
        print(f"Client {client_id} error: {str(e)}")


if __name__ == "__main__":
    print("===== FAST RETRANSMIT TEST =====")
    print("Testing fast retransmit on triple duplicate ACK")

    # Start client
    client_thread = threading.Thread(target=client_operation, args=(1,))
    client_thread.start()
    client_thread.join()

    print("===== TEST COMPLETED =====")