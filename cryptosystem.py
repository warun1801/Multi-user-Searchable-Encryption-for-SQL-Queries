import random
import pickle
from collections import defaultdict
from cryptography.fernet import Fernet
from pypbc import *
from elgamal import elgamal_encrypt_block, elgamal_decrypt_block
from generation_utils import key_byte_to_int, key_int_to_byte
from dict_creation import create_keyword_set, fetch_table, create_dictionary

import faulthandler
faulthandler.enable()
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

# 4.4 ALGOS
def init_ca_params(params):
    msk = Element.random(params["e"], Zr)
    P = Element(params["e"], G1, value= params["g"] ** msk)
    return msk, P

def skeyGen(params, attr_list, msk, public_key_to_encrypt):
    attr_string = "".join(attr_list)
    Q = params["h1"](attr_string)
    # ak is the attribute private key
    ak = Element(params["e"], G1, value=Q ** msk)
    # Now encrypt ak using the proxy public key
    print("--------------------------")
    print("ak=",ak)
    
    # print(str(ak))
    int_val = key_byte_to_int(str(ak).encode())
    # # Steps to preserve the ak
    # new_ak = Element(params["e"], G1, value=key_int_to_byte(int_val).decode())
    # print(new_ak)
    # Encrypt ak
    print("******************************")
    print('int_val = ', int_val)
    # print('order is ', params['q'])
    # ak_enc = elgamal_encrypt(int_val, params['g'], params['e'], public_key_to_encrypt, params['q'])
    block_size = len(str(int(params['q'])))-1
    ak_enc, len_msg = elgamal_encrypt_block(int_val, params['g'], params['e'], public_key_to_encrypt, params['q'], block_size)
    # print(ak_enc)
    print("--------------------------")
    return ak_enc, len_msg

def decrypt_ak(params, ak_enc, private_key_to_decrypt, len_msg):
    print("-------------------")
    # print('order is ', params['q'])
    # ak_val = elgamal_decrypt(c1, c2, params['e'], private_key_to_decrypt, params['g'], params['q'])
    block_size = len(str(int(params['q'])))-1
    ak_val = elgamal_decrypt_block(ak_enc, params['g'], params['e'], private_key_to_decrypt, params['q'], len_msg, block_size)
    print('ak_val:',ak_val)
    ak = Element(params["e"], G1, value=key_int_to_byte(ak_val).decode())
    print("------------------")
    return ak

def encryTrans(params, attr_list, data_owner_sk, data_user_pk, sym_key, P):
    attr_string = "".join(attr_list)
    Q = params["h1"](attr_string)
    v = Element.random(params["e"], Zr)
    g_power_xy = Element(params["e"], G1, value= data_user_pk ** data_owner_sk)
    # Unsure steps
    print('v is ',v)
    print('sym key is ',sym_key)
    v_dash = int(params['h2'](g_power_xy)) +int(v)
    pairing_value = params["e"].apply(Q, P) ** v
    # Do XOR between pairing_value and sym_key here
    # TODO: Implement XOR
    # Get the int of sym_key
    int_key =  key_byte_to_int(sym_key)
    xor_value = int_key ^ int(params['h2'](pairing_value))
    c = v_dash, xor_value
    print('int key :', int_key)
    print('pairing_value as int:', int(params['h2'](pairing_value)))
    print("c in encry:",c)
    return c

def decryTrans(params, c, ak_enc, data_owner_pk, data_user_sk, len_msg):
    print("c in decry:",c)
    v_dash, V = c
    g_power_xy = Element(params["e"], G1, value= data_owner_pk ** data_user_sk)
    # Unsure step
    v = v_dash - int(params['h2'](g_power_xy))
    v = Element(params["e"], Zr, value=v)
    print('v is ',v)
    # Decrpyt V
    ak = decrypt_ak(params, ak_enc, data_user_sk, len_msg)
    print("ak is ",ak)
    pairing_value = params["e"].apply(ak, params["g"]) ** v
    hash_pairing_value = params["h2"](pairing_value)
    # Do XOR between hash_pairing_value and V here
    print('hash_pairing_value is ',hash_pairing_value)
    int_key = V ^ int(hash_pairing_value)
    print('int key is ',int_key)
    sym_key = key_int_to_byte(int_key)
    print('sym key is ',sym_key)
    return sym_key

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
    msk, P = init_ca_params(params)
    attr_list = ["dhruv", "warun"]
    ak_enc, len_msg = skeyGen(params, attr_list, msk, data_user_pk)

    # # test decryption of ak
    # ak = decrypt_ak(params, ak_enc, data_user_sk, len_msg)
    # print(f"mod q: {params['q']}")
    # Test trans functions
    print("###################")
    c = encryTrans(params, attr_list, private_key, data_user_pk, sym_key, P)
    print("###################")
    key = decryTrans(params, c, ak_enc, public_key, data_user_sk, len_msg)



if __name__ == "__main__":
    main()