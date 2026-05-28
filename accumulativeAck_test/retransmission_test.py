import threading
import time
from clientV3 import TcpOverUdpClient


def client_operation(client_id, delay=0):
    try:
        time.sleep(delay)
        print(f"\n--- Client {client_id} starting ---")
        client = TcpOverUdpClient()

        # Connect with retry
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                client.connect()
                break
            except ConnectionError:
                if attempt < max_attempts - 1:
                    print(f"Client {client_id} retrying connection...")
                    time.sleep(1)
                else:
                    raise

        print(f"Client {client_id} connected")

        # Send message that will be "lost"
        message = "Important data " 
        client.send(message)
        message = "Important data 1"
        client.send(message)
        message = "Important data 2"
        client.send(message)
        print(f"Client {client_id} sent: {message}")

        # Wait for response
        response = client.receive(1024, timeout=5)
        if response:
            decrypted = client.encryptor.decrypt(response)
            print(f"Client {client_id} received: {decrypted}")
        else:
            print(f"Client {client_id} no response received")

        # Close connection
        print(f"Client {client_id} closing...")
        client.close()
        print(f"--- Client {client_id} finished ---")

    except Exception as e:
        print(f"Client {client_id} error: {str(e)}")


if __name__ == "__main__":
    print("===== RETRANSMISSION TEST =====")
    print("This test will simulate packet loss and retransmission")

    # Start clients with staggered timing
    clients = [
        threading.Thread(target=client_operation, args=(1, 0))
       # threading.Thread(target=client_operation, args=(2, 2)),
       # threading.Thread(target=client_operation, args=(3, 4))
    ]

    for client in clients:
        client.start()

    for client in clients:
        client.join()

    print("===== TEST COMPLETED =====")