"""
Elliptic Curve Elgamal implementation to encrypt and decrypt symmetric keys for algorrithms mentioned in the paper
"""
import pypbc
from pypbc import *
import warnings
from generation_utils import key_byte_to_int, key_int_to_byte
from cryptography.fernet import Fernet

warnings.filterwarnings("ignore", category=DeprecationWarning) 

def key_to_int(key):
    # Parse the key bits as a binary integer
    return int(key)

def int_to_key(key):
    # TODO: Key size padding with 0's in start to be implemented
    bin_key = bin(key)
    return str(bin_key)


def generate_keys(k):
    param = Parameters(qbits=4*k,rbits=k)
    pairing = Pairing(param)
    # print(str(param))
    q = int(str(param).split("\n")[1].split(" ")[1])
    # print(q)
    g = Element.random(pairing, G1)
    private_key = Element.random(pairing, Zr)
    public_key = Element(pairing, G1, value=g**private_key)
    return pairing, private_key, public_key, g, q

def elgamal_encrypt(msg, g, pairing, public_key, q):
    # Choose random k
    k = Element.random(pairing, Zr)
    # Compute C1 = g^k
    C1 = Element(pairing, G1, value=g**k)
    # Compute C2 = msg + h(k*publci_key) mod q
    k_pk = Element(pairing, G1, value = public_key**k)
    hash_value = Element.from_hash(pairing, Zr, str(k_pk))
    # print(int(hash_value))
    C2 = ( msg + int(hash_value) ) % q
    return C1, C2

def elgamal_decrypt(C1, C2, pairing, private_key, g, q):
    R = Element(pairing, G1, value=C1**private_key)
    hash_value = Element.from_hash(pairing, Zr, str(R))
    message = (C2 - int(hash_value)) % q
    # print(message)
    return message



if __name__ == "__main__":
    # Generate a key pair
    pairing, private_key, public_key, g, q = generate_keys(1024)
    # # Encrypt a message
    sym_key = Fernet.generate_key()
    print(f"Symmetric key: {sym_key}")



    # msg = int(input("Enter a message: "))
    msg = key_byte_to_int(sym_key)
    C1, C2 = elgamal_encrypt(msg, g, pairing, public_key, q)
    print("C1 =", C1)
    print("C2 =", C2)
    # # Decrypt the message
    msg_decrypted = elgamal_decrypt(C1, C2, pairing, private_key, g, q)
    print(f"Decrypted message: {key_int_to_byte(msg_decrypted)}")
    # # Check that the decrypted message is the same as the original
    # assert msg == msg_decrypted