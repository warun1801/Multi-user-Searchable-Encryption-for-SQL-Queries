import random
import pickle
from collections import defaultdict
from cryptography.fernet import Fernet
from pypbc import *
from elgamal import elgamal_encrypt, elgamal_decrypt
from dict_creation import create_keyword_set, fetch_table, create_dictionary


# All algos mentioned in the paper

# Generate the parameters
def setup(k):
    
    param = Parameters(qbits=4*k, rbits=k)
    ls = list(str(param).split("\n"))
    
    # this is actually order of the group
    q = int(ls[3].split(" ")[1])
    pairing = Pairing(param)
    g = Element.random(pairing, G1)

    # define the hash functions
    def hash1(message):
        return Element.from_hash(pairing, G1, str(message))

    def hash2(element):
        return Element.from_hash(pairing, Zr, str(element))

    def hash3(message):
        return Element.from_hash(pairing, Zr, str(message))
    
    return {
            "q": q,
            "e": pairing,
            "g": g,
            "h1": hash1,
            "h2": hash2,
            "h3": hash3
            } #params

# Generate pk, sk for data owner/user
def keyGen(params):
    pairing = params["e"]
    g = params["g"]
    private_key = Element.random(pairing, Zr)
    public_key = Element(pairing, G1, value=g**private_key)
    return private_key, public_key

# Generate the keyword index
def encIndex(table, params, private_key):
    W = create_keyword_set(table)
    r = random.randint(0, params['q'] - 1)
    
    x = private_key

    enc_indices = defaultdict()
    for w in W:
        enc_indices[w] = params['e'].apply(
                                                Element(params['e'], G1, value=params['h1'](w) ** int(x)),
                                                Element(params['e'], G2, value=params['g'] ** r)
                                                )
    # pprint(enc_indices)
    return enc_indices, r

# To encrypt the table
def encTable(tables, sym_key):
    f = Fernet(sym_key)
    C = []
    for table in tables:
        C.append(f.encrypt(pickle.dumps(table)))
    return C

# Generate the trapdoor
def trapdoor(params, owner_public_key, user_private_key, query_words):
    g_power_xy = Element(params["e"], G1, value= owner_public_key ** user_private_key)
    a, b = str(g_power_xy[0]), str(g_power_xy[1])
    tk = params['h3'](a + b)
    # Use tk to generate the trapdoor
    Td = []
    for word in query_words:
        Td.append(Element(params["e"], G1, value = params['h1'](word)))
    return Td

# Access control
def delegate(params, r, owner_private_key, user_public_key, C):
    # Get the trapdoor for g_power_xy
    g_power_xy = Element(params["e"], G1, value= user_public_key ** owner_private_key)
    a, b = str(g_power_xy[0]), str(g_power_xy[1])
    tk = params['h3'](a + b)
    rx = r * int(owner_private_key)
    zeta = Element(params["e"], G2, params['g'] ** rx)
    eta = Element(params["e"], G1, params['g'] ** tk)
    # Here we can check via public key to which tables user has access to, and do the following steps only for those tables
    Acd = []
    for c in C:
        Acd.append([c, zeta, eta])
    return Acd

# Next algo here
def dlist(params, Acd, Td, I):
    matches = []
    for c, zeta, eta in Acd:
        denominator = params["e"].apply(eta, params["g"])
        for t in Td:
            # print(f"Td: {t}")
            numerator = params["e"].apply(t, zeta)
            for key, value in I.items():
                # print(f"Num/Denom = {numerator}")
                # print(f"Value = {value}")
                if numerator ==  value:
                    # print("Found a match")
                    matches.append(key)

    return matches


def main():
    # Setup the params
    params = setup(10)
    # Generate a key-pair
    private_key, public_key = keyGen(params)
    print( "public_key =", public_key)
    print( "private_key =", private_key)
    # Get the table
    table = fetch_table("data/table2.csv")
    word_to_row_data = create_dictionary(table)
    # Create the keyword index
    I, r = encIndex(table, params, private_key) # r choosen by data owner
    # print(I)

    # print(word_to_row_data)

    # # Get a symmteric key to encrypt the tables
    sym_key = Fernet.generate_key()
    binary_key = ''.join(format(ord(i), '08b') for i in sym_key.decode())
    # print(sym_key)
    # print(binary_key, len(binary_key))
    # print("Int key =", int(binary_key, 2))
    # # Encrypt the tables
    tables = ["data/table1.csv"]
    C = encTable(tables, sym_key)
    # print(C)
    # Get the query words and generate the trapdoor
    data_user_sk, data_user_pk = keyGen(params)
    query_words = ["dhruv", "warun"]
    Td = trapdoor(params, public_key, data_user_sk, query_words)
    print(f"Trapdoor: {Td}")
    # # Generate the ACD for access control
    # # print(r)
    Acd = delegate(params, r, private_key, data_user_pk, C)
    print(f"ACD: {Acd}")
    # # Get the row/keyword matches
    # print(I.values())

    matches = dlist(params, Acd, Td, I)

    # print(params["e"].apply(params["h1"]("dhruv") ** 2, params["g"] ** 10) == params["e"].apply(params["h1"]("dhruv"), params["g"] ** 20))
    # print(matches)


if __name__ == "__main__":
    main()