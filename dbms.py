from mimetypes import init
import socket
import threading
from time import sleep
from pypbc import *
from collections import defaultdict
from cryptosystem import dlist
import pickle
import sys
import argparse

class Table:
    def __init__(self, tableName, encTable, encIndices, ownerId, A):
        self.tableName = tableName
        self.encTable = encTable
        self.encIndices = encIndices
        self.ownerId = ownerId
        self.A = A
        self.tableId = (ownerId, tableName)


class DBMSServer:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)
        self.clients = defaultdict(lambda: None)
        self.store = defaultdict(lambda: None)
        self.Acd = defaultdict(lambda: None)
        self.params = []
        self.threads = defaultdict(lambda: None)

    def fix_params(self):
        self.params["e"] = Pairing(Parameters(param_string=self.params["e"]))
        self.params["g"] = Element(self.params["e"], G1, value=self.params["g"])

        def hash1(message):
            return Element.from_hash(self.params["e"], G1, str(message))

        def hash2(element):
            return Element.from_hash(self.params["e"], Zr, str(element))

        def hash3(message):
            return Element.from_hash(self.params["e"], Zr, str(message))

        self.params["H1"] = hash1
        self.params["H2"] = hash2
        self.params["H3"] = hash3

    def add_client(self, clientId, conn):
        self.clients[clientId] = conn

    def remove_client(self, clientId):
        self.clients[clientId].close()
        del self.clients[clientId]

    def add_table(self, table):
        self.store[table.tableId] = table

    def remove_table(self, tableId):
        del self.store[tableId]

    def query(self, tableName, ownerId, userId, A):
        dataUserConn = self.clients[userId]
        dataOwnerConn = self.clients[ownerId]
        
        # generate trapdoor
        dataUserConn.send(b'Send Trapdoor')

        Td = dataUserConn.recv(1000000)
        Td = pickle.loads(Td)
        for i, td in enumerate(Td):
            Td[i] = Element(self.params["e"], G1, value=td)

        print(f"Trapdoor: {Td}")

        while self.Acd[(userId, ownerId, tableName)] == None:
            continue

        Acd = self.Acd[(userId, ownerId, tableName)]
        # print("Got ACD")
        print(f"ACD: {Acd}")
        # dlist
        table = self.store[(ownerId, tableName)]
        
        # print(f"Table: {table}")
        I = table.encIndices
        dlistWords = dlist(self.params, Acd, Td, I)
        matches = defaultdict(list)

        for i in dlistWords:
            matches[i] = A[i]

        print("Searchable Encryption Matches:", matches)
        dataUserConn.send(pickle.dumps(matches))

    def start_server(self):
        try:
            # certification authority
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conn.bind((self.host, self.port))

            conn.connect(('127.0.0.1', 8080))
            print('Connected to Certification Authority for getting Params')
            params = conn.recv(1000000)
            params, P = pickle.loads(params)
            self.params = params
            self.fix_params()
            print('Params fixed!')
            # print(self.params)
            conn.send(b'done')
            conn.close()

            serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            serv.bind((self.host, self.port))
            print(f"DBMS Server started on {self.host}:{self.port}")
            serv.listen(5)

            while True:
                conn, addr = serv.accept()
                print(f"Connected to proxy server: {addr[1]}")
                self.add_client(addr[1], conn)
                # print(f"Client {addr[1]} added")
                # print(self.clients)
                self.threads[addr[1]] = threading.Thread(target=self.handle_proxy, args=(conn,))
                self.threads[addr[1]].start()


        except socket.error as e:
            open('data/public_keys.csv', 'w').close()
            print(f"Socket Error: {e}")
            sys.exit(1)

        except KeyboardInterrupt:
            open('data/public_keys.csv', 'w').close()
            sys.exit(1)

    def handle_proxy(self, conn):
        while True:
            conn.send(b'What type of operations do you want to do? 1. Add table 2. Query 3. Exit from server')
            op = conn.recv(1000000)

            if op == b'1':
                print("-" * 30)
                print("Type 1: Add Table")

                conn.send(b'Send Table info Format: (tableName, ownerId, encTable, encIndices, A)\n')

                tableInfo = conn.recv(1000000)
                tableName, ownerId, encTable, encIndices, A = pickle.loads(tableInfo)

                for key, value in encIndices.items():
                    encIndices[key] = Element(self.params["e"], GT, value=value)

                table = Table(tableName, encTable, encIndices, ownerId, A)
                self.add_table(table)
                conn.send(b'Table added successfully\n')
                sleep(2)
                print("Table added successfully into the DBMS")
                print("-" * 30)
            
            elif op == b'2':
                print("-" * 30)
                print("Type 2: Query Request")

                conn.send(b'Send Query Info Format(tableName, ownerId, userId)')
                queryInfo = conn.recv(1000000)
                tableName, ownerId, userId = pickle.loads(queryInfo)
                table = self.store[(ownerId, tableName)]
                self.query(tableName, ownerId, userId, table.A)
                
                print("-" * 30)
            
            elif op == b'3':
                print("-" * 30)
                print("Type 3: Waiting for delegation")
                
                conn.send(b'Send Query Info Format(tableName, ownerId, userId)')
                queryInfo = conn.recv(1000000)
                tableName, ownerId, userId = pickle.loads(queryInfo)
                print(f"Table Name: {tableName} Owner Id: {ownerId} User Id: {userId}")

                if not self.Acd[(userId, ownerId, tableName)]:
                    # generate delegate list
                    Acd = conn.recv(1000000)
                    Acd = pickle.loads(Acd)
                    for i, acd in enumerate(Acd):
                        Acd[i] = [acd[0], Element(self.params["e"], G2, value=acd[1]), Element(self.params["e"], G1, value=acd[2])]
                    
                    self.Acd[(userId, ownerId, tableName)] = Acd
                print(f"Delegate List: {self.Acd[(userId, ownerId, tableName)]}")
                print("-" * 30)

            else:
                print("Exiting from the DBMS Server")
                break
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", help="Port to listen on", type=str, default="8004")
    parser.add_argument("--host", help="Host to listen on", type=str, default="127.0.0.1")
    args = parser.parse_args()

    host = args.host
    port = args.port

    s = DBMSServer(host, port)
    t = threading.Thread(target=s.start_server)
    t.start()
    
    for si in s.threads.values():
        si.join()

    # t.join()

            

