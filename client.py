from collections import defaultdict
import socket
from dict_creation import create_keyword_set
from generation_utils import key_gen
import argparse
import sys
import pickle
import pprint
import random
from cryptography.fernet import Fernet

from pypbc import Pairing, Parameters, Element, G1, Zr

class Proxy:
    # Setup
    def __init__(self, connection_host, connection_port):
        self.conn_host = connection_host
        self.conn_port = int(connection_port)
        self.PARAMS = {}
        self.public_key = ""
        self.private_key = ""

    def fix_params(self):
        self.PARAMS["e"] = Pairing(Parameters(param_string=self.PARAMS["e"]))
        self.PARAMS["g"] = Element(self.PARAMS["e"], G1, value=self.PARAMS["g"])

        def hash1(message):
            return Element.from_hash(self.PARAMS["e"], G1, str(message))

        def hash2(element):
            return Element.from_hash(self.PARAMS["e"], Zr, str(element))

        def hash3(message):
            return Element.from_hash(self.PARAMS["e"], Zr, str(message))

        self.PARAMS["H1"] = hash1
        self.PARAMS["H2"] = hash2
        self.PARAMS["H3"] = hash3

    # FOR THE DATA OWNER
    def enc_index(self, table):
        W = create_keyword_set(table)
        r = random.randint(0, self.PARAMS['q'] - 1)
        self.r = r
        x = self.private_key

        enc_indices = defaultdict()
        for w in W:
            enc_indices[w] = self.PARAMS['e'].apply(
                                                    Element(self.PARAMS['e'], G1, value=self.PARAMS['H1'](w) ** x),
                                                    Element(self.PARAMS['e'], G1, value=self.PARAMS['g'] ** r)
                                                    )
        # pprint(enc_indices)
        return enc_indices

    def encrypt_tables(self, tables, sym_key):
        f = Fernet(sym_key)
        C = []
        for table in tables:
            C.append(f.encrypt(pickle.dumps(table)))
        return C

    
    def delegate(self, user_public_key, C):
        x = self.private_key
        gy = user_public_key

        gxy = Element(self.PARAMS['e'], G1, value=gy**x)
        a, b = str(gxy[0]), str(gxy[1])
        tk = self.PARAMS['H3'](a + b)

        zeta = self.PARAMS['g'] ** (self.r * x)
        eta = self.PARAMS['g'] ** tk

        Acd = []
        for c in C:
            Acd.append([c, zeta, eta])
        return Acd


    # FOR THE DATA USER
    def trapdoor(self, owner_public_key, query_words):
        gx = owner_public_key
        y = self.private_key

        gxy = Element(self.PARAMS['e'], G1, value=gx**y)
        a, b = str(gxy[0]), str(gxy[1])
        tk = self.PARAMS['H3'](a + b)

        Td = []
        for word in query_words:
            Td.append(self.PARAMS['H1'](word) ** tk)

        # pprint(f"Trapdoor: {Td}")
        return Td



    # Connection details and main of the class
    def start_proxy(self):
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((self.conn_host, self.conn_port))
            print(f"Client Connected to {self.conn_host}:{self.conn_port}")

            data = conn.recv(10000000)
            
            self.PARAMS = pickle.loads(data)
            self.fix_params()
            print("Received", end=" ")
            pprint.pprint(self.PARAMS)

            self.public_key, self.private_key = key_gen(self.PARAMS)
            print(f"public_key = {self.public_key}\nprivate_key = {self.private_key}")

            conn.send(pickle.dumps((str(self.public_key), str(self.private_key))))
            conn.close()


        except socket.error as e:
            print(f"Socket Error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Proxy")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=str, default="8080")
    args = parser.parse_args()

    host = args.host
    port = args.port

    proxy = Proxy(host, port)
    proxy.start_proxy()

