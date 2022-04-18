import argparse
import enum
import socket
import sys
import threading
import pprint
from xml.dom.minidom import Element
from cryptosystem import init_ca_params, skeyGen
from generation_utils import setup
import pickle
from pypbc import *

class CertificationAuthServer:
    def __init__(self, host, port):
        self.CLIENTS = []
        self.PARAMS = setup(10)
        self.host = host
        self.port = int(port)
        self.client_count = 0
        self.msk, self.P = init_ca_params(self.fix_params())

    def fix_params(self):
        params = self.PARAMS.copy()
        params["e"] = Pairing(Parameters(param_string=params["e"]))
        params["g"] = Element(params["e"], G1, value=params["g"])

        def hash1(message):
            return Element.from_hash(params["e"], G1, str(message))

        def hash2(element):
            return Element.from_hash(params["e"], Zr, str(element))

        def hash3(message):
            return Element.from_hash(params["e"], Zr, str(message))

        params["H1"] = hash1
        params["H2"] = hash2
        params["H3"] = hash3

        # print(params)
        return params

    def start_server(self):
        try:
            serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serv.bind((self.host, self.port))
            print(f"CA Server started on {self.host}:{self.port}")
            serv.listen(5)
            # serv.settimeout(120)

            while True:
                try:
                    conn, addr = serv.accept()
                    print(f"Connected to client: {addr}")

                    self.client_count += 1
                    # print(f"Client Count: {self.client_count}")

                    self.CLIENTS.append(conn)
                    threading.Thread(target=self.handle_client, args=(conn, addr)).start()
                except Exception as e:
                    print(f"Error: {e}")
                except KeyboardInterrupt:
                    break
            serv.close()

        except socket.error as e:
            print(f"Socket Error: {e}")
            sys.exit(1)

    def handle_client(self, conn, addr):
        conn.send(pickle.dumps((self.PARAMS, str(self.P))))
        conn.settimeout(120)
        
        data = conn.recv(1000000)
        if (not data) or data == b'done':
            return

        data = pickle.loads(data)
        private_key = Element(self.fix_params()["e"], G1, value=data)

        # generate secret key
        attr_list = ["name", "name", "name"]
        ak_enc, len_msg = skeyGen(self.fix_params(), attr_list, self.msk, private_key)
        if addr[1] == 6002:
            print("Sending skey to data user")
            # print(f"ak_enc: {ak_enc} len_msg: {len_msg}")

            for i, val in enumerate(ak_enc):
                ak_enc[i] = (str(val[0]), val[1])

            conn.send(pickle.dumps((ak_enc, len_msg)))
        
        # pprint.pprint(f"Received: {data}")
        with open('data/public_keys.csv', 'a') as f:
            f.write(f"{addr[1]},{data}\n")

        self.CLIENTS.remove(conn)
        self.client_count -= 1
        # print(f"Removed 1 client. Client Count: {self.client_count}")
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

        