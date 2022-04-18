from collections import defaultdict
import socket
from time import sleep
from dict_creation import create_keyword_set, get_table_info
from generation_utils import key_gen
import argparse
import sys
import pickle
import pprint
import random
from cryptography.fernet import Fernet

from pypbc import Pairing, Parameters, Element, G1, Zr, G2, GT

ownerId = 6001
userId = ownerId + 1

class Proxy:
    # Setup
    def __init__(self, host, port):
        self.ca_host = '127.0.0.1'
        self.ca_port = 8080
        self.dbms_host = '127.0.0.1'
        self.dbms_port = 8004
        self.my_host  = host
        self.my_port = int(port)
        self.sym_key = Fernet.generate_key()

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
            enc_indices[w] = str(self.PARAMS['e'].apply(
                                                    Element(self.PARAMS['e'], G1, value=self.PARAMS['H1'](w) ** x),
                                                    Element(self.PARAMS['e'], G1, value=self.PARAMS['g'] ** r)
                                                    ))
        # pprint(enc_indices)
        return enc_indices

    def encrypt_tables(self, tables, sym_key):
        f = Fernet(sym_key)
        C = []
        for table in tables:
            C.append(f.encrypt(pickle.dumps(table)))
        return C

    
    def delegate(self, user_public_key, C):
        # Get the trapdoor for g_power_xy
        g_power_xy = Element(self.PARAMS["e"], G1, value= user_public_key ** self.private_key)
        a, b = str(g_power_xy[0]), str(g_power_xy[1])
        tk = self.PARAMS['H3'](a + b)
        rx = self.r * int(self.private_key)
        zeta = Element(self.PARAMS["e"], G2, self.PARAMS['g'] ** rx)
        eta = Element(self.PARAMS["e"], G1, self.PARAMS['g'] ** tk)
        # Here we can check via public key to which tables user has access to, and do the following steps only for those tables
        Acd = []
        for c in C:
            Acd.append([c, str(zeta), str(eta)])
        return Acd
        


    # FOR THE DATA USER
    def trapdoor(self, owner_public_key, query_words):
        g_power_xy = Element(self.PARAMS["e"], G1, value= owner_public_key ** self.private_key)
        a, b = str(g_power_xy[0]), str(g_power_xy[1])
        tk = self.PARAMS['H3'](a + b)
        # Use tk to generate the trapdoor
        Td = []
        for word in query_words:
            Td.append(str(Element(self.PARAMS["e"], G1, value = self.PARAMS['H1'](word))))
        return Td


    def encrypt_trans(self, attr_list, data_owner_sk, data_user_pk, symmetric_key, P):
        attr_string = "".join(attr_list)
        Q = self.PARAMS["H1"](attr_string)
        # Randomly select v from Zq
        v = Element.random(self.PARAMS["e"], Zr)
        g_power_xy = Element(self.PARAMS["e"], G1, value= data_user_pk ** data_owner_sk)
        # Below steps are not clear in the paper so as to what + means
        v_dash = g_power_xy + v
        pairing_value = self.PARAMS["e"].apply(P, Q)
        pairing_value = Element(self.PARAMS["e"], G1, value=pairing_value ** v)
        hash_pairing_value = self.PARAMS["H2"](pairing_value)
        # Cipher text is <v_dash, Symmetric_key XOR hash_pairing_value>
        # return cipher text 

    def decrypt_symmetric_key(self, c, ak, data_user_sk, data_owner_pk):
        v_dash, V = c
        g_power_xy = Element(self.PARAMS["e"], G1, value= data_owner_pk ** data_user_sk)
        v = v_dash - g_power_xy
        # Decrpyt V
        pairing_value = self.PARAMS["e"].apply(ak, self.PARAMS["g"])
        pairing_value = Element(self.PARAMS["e"], G1, value=pairing_value ** v)
        hash_pairing_value = self.PARAMS["H2"](pairing_value)
        # symmetric_key = V XOR hash_pairing_value



    # Connection details and main of the class
    def start_proxy(self):
        global ownerId
        global userId
        try:
            # Certification Authority
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conn.bind((self.my_host, self.my_port))
            conn.connect((self.ca_host, self.ca_port))
            print(f"Proxy Server connected to Certification Authority:{self.ca_port}")

            data = conn.recv(10000000)
            
            self.PARAMS = pickle.loads(data)
            self.fix_params()

            print("-"*30)
            print("Params", end=" ")
            pprint.pprint(self.PARAMS)
            print("-"*30)

            self.public_key, self.private_key = key_gen(self.PARAMS)
            print(f"public_key = {self.public_key}\nprivate_key = {self.private_key}")

            conn.send(pickle.dumps((str(self.public_key))))
            conn.close()

            # Data Owner
            # conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conn.bind((self.my_host, self.my_port))
            conn.connect((self.dbms_host, self.dbms_port))

            while True:
                question = conn.recv(10000000)
                if question == b'What type of operations do you want to do? 1. Add table 2. Query 3. Exit from server':
                    op = int(input("What type of operations do you want to do?\n1. Add table\n2. Query\n3. Listen for Requests\n=>"))
                    conn.send(str(op).encode())

                    if op == 1:
                        print("-"*30)
                        res = conn.recv(1000000).decode()
                        print(res)

                        table_name = "data/table2.csv"
                        table, W, A = get_table_info(table_name)
                        encTable = self.encrypt_tables([table], self.sym_key)
                        encIndices = self.enc_index(table)
                        ownerId = self.my_port
                        conn.send(pickle.dumps((table_name, ownerId, encTable, encIndices, A)))
                        print(conn.recv(1000000).decode())
                        print("-"*30)

                    if op == 2:
                        print("-"*30)
                        res = conn.recv(1000000).decode()
                        print(res)

                        table_name = "data/table2.csv"
                        # ownerId = 6005
                        # userId = 6006

                        conn.send(pickle.dumps((table_name, ownerId, userId)))

                        # trapdoor request
                        trapdoor_request = conn.recv(1000000)
                        query_words = ['warun', 'dhruv', 'samruddhi']
                        
                        with open('data/public_keys.csv') as f:
                            lines = f.readlines()
                            owner_pub_key = ''
                            for line in lines:
                                data = line.strip().split(',')
                                owner_id = int(data[0])
                                if owner_id == ownerId:
                                    owner_pub_key = data[1]

                        # print(f"Owner public key: {owner_pub_key}")
                        owner_pub_key = Element(self.PARAMS["e"], G1, value=owner_pub_key)
                        td = self.trapdoor(owner_pub_key, query_words)
                        print(f"Trapdoor: {td}")
                        conn.send(pickle.dumps(td))
                        print("Sent Trapdoor!")

                        Matchlist = conn.recv(1000000)
                        print(f"Searchable Encryption Matches: {pickle.loads(Matchlist)}")
                        print("-"*30)

                    if op == 3:
                        print("-"*30)
                        res = conn.recv(1000000).decode()
                        print(res)

                        table_name = "data/table2.csv"
                        # ownerId = 6005
                        # userId = 6006

                        conn.send(pickle.dumps((table_name, ownerId, userId)))
                        
                        with open('data/public_keys.csv') as f:
                            lines = f.readlines()
                            user_pub_key = ''
                            for line in lines:
                                data = line.strip().split(',')
                                # print(data)
                                user_id = int(data[0])
                                if user_id == userId:
                                    user_pub_key = data[1]

                        # print(F"User public key: {user_pub_key}")
                        user_pub_key = Element(self.PARAMS["e"], G1, value=user_pub_key)
                        Acd = self.delegate(user_pub_key, [1])
                        print(f"Acd: {Acd}")
                        sleep(2)
                        conn.send(pickle.dumps(Acd))
                        print("Sent Acd!")
                        print("-"*30)


        except socket.error as e:
            open('data/public_keys.csv', 'w').close()
            print(f"Socket Error: {e}")
            sys.exit(1)

        except KeyboardInterrupt:
            open('data/public_keys.csv', 'w').close()
            sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Proxy")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=str, default="6001")
    args = parser.parse_args()

    host = args.host
    port = args.port

    proxy = Proxy(host, port)
    proxy.start_proxy()

