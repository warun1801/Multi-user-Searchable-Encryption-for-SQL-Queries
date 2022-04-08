import argparse
import socket
import sys
import threading
import pprint
from generation_utils import setup
import pickle


class CertificationAuthServer:
    def __init__(self, host, port):
        self.CLIENTS = []
        self.PARAMS = setup(10)
        self.host = host
        self.port = int(port)
        self.client_count = 0

    def start_server(self):
        try:
            serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serv.bind((self.host, self.port))
            print(f"Server started on {self.host}:{self.port}")
            serv.listen(5)
            # serv.settimeout(120)

            while True:
                try:
                    conn, addr = serv.accept()
                    print(f"Connected to client: {addr}")

                    self.client_count += 1
                    print(f"Client Count: {self.client_count}")

                    self.CLIENTS.append(conn)
                    threading.Thread(target=self.handle_client, args=(conn,)).start()
                except Exception as e:
                    print(f"Error: {e}")
                except KeyboardInterrupt:
                    break
            serv.close()

        except socket.error as e:
            print(f"Socket Error: {e}")
            sys.exit(1)

    def handle_client(self, conn):
        conn.send(pickle.dumps(self.PARAMS))
        conn.settimeout(120)
        while True:
            data = conn.recv(1000000)
            if not data:
                break

            data = pickle.loads(data)
            pprint.pprint(f"Received: {data}")

        self.CLIENTS.remove(conn)
        self.client_count -= 1
        print(f"Removed 1 client. Client Count: {self.client_count}")
        conn.close()

    def broadcast(self, message):
        for client in self.CLIENTS:
            try:
                client.send(message.encode())
            except socket.error as e:
                print(f"Error: {e}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", help="Port to listen on", type=str, default="8080")
    parser.add_argument("--host", help="Host to listen on", type=str, default="127.0.0.1")
    args = parser.parse_args()

    host = args.host
    port = args.port

    s = CertificationAuthServer(host, port)
    threading.Thread(target=s.start_server).start()

        