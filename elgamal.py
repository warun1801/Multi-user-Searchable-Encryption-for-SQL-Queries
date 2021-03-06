"""
Elliptic Curve Elgamal implementation to encrypt and decrypt symmetric keys for algorrithms mentioned in the paper
"""
import math
import pypbc
from pypbc import Parameters, Pairing, Element, G1, Zr
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
    # print(f"Pairing: {pairing}")


    kerpk = Element(pairing, G1, value=public_key**k)
    hash_value = Element.from_hash(pairing, Zr, str(kerpk))
    # print(int(hash_value))
    C2 = ( msg + int(hash_value) ) % q
    return C1, C2

def elgamal_decrypt(C1, C2, pairing, private_key, g, q):
    R = Element(pairing, G1, value=C1**private_key)
    hash_value = Element.from_hash(pairing, Zr, str(R))
    message = (C2 - int(hash_value)) % q
    # print(message)
    return message

def elgamal_encrypt_block(msg, g, pairing, public_key, q, block_size = 40):
    # Assume that msg is a long integer
    str_msg = str(msg)
    len_msg = len(str_msg)
    iters = math.ceil(len_msg / block_size)
    # print("Iterations: ", iters)
    # print("Total length of data: ", len_msg)
    encrypted_data = []
    for i in range(iters):
        block_data = str_msg[i*block_size:(i+1)*block_size]
        # print(f"block_data {i}: {block_data}")
        block_int = int(block_data)
        encryption = elgamal_encrypt(block_int, g, pairing, public_key, q)
        encrypted_data.append(encryption)
    return encrypted_data, len_msg

def elgamal_decrypt_block(encrypted_data, g, pairing, private_key, q, len_msg ,block_size = 40):
    decrypted_data = []
    for i in encrypted_data:
        # print(f"I = {i}")
        decryption = elgamal_decrypt(i[0], i[1], pairing, private_key, g, q)
        # print(f"decryption : {decryption}")
        decrypted_data.append(decryption)
    # Combine to single int-string
    str_msg = ""
    iters = math.ceil(len_msg / block_size)
    for i in range(iters):
        if i != iters -1:
            block_data = str(decrypted_data[i]).zfill(block_size)
            str_msg += block_data
        else:
            # print("Here")
            block_data = str(decrypted_data[i]).zfill(len_msg % block_size)
            str_msg += block_data
    # print("Reconstructed length: ", len(str_msg))
    return int(str_msg)


if __name__ == "__main__":
    # Generate a key pair
    pairing, private_key, public_key, g, q = generate_keys(100)
    # # Encrypt a message
    # sym_key = Fernet.generate_key()
    # print(f"Symmetric key: {sym_key}")

    sym_key = Element.random(pairing, G1)

    msg = key_byte_to_int(str(sym_key).encode())
    # print(f"Symmetric key: {sym_key}")
    # print(f"Message: {msg}")
    encrypted_data, len_msg = elgamal_encrypt_block(msg, g, pairing, public_key, q)
    # print(f"Encrypted data: {encrypted_data}")
    # # Decrypt the message
    decrypted_data = elgamal_decrypt_block(encrypted_data, g, pairing, private_key, q, len_msg)
    # print(f"Decrypted data: {decrypted_data}")

    # # Convert the decrypted data to a key
    decrypted_key = key_int_to_byte(decrypted_data)
    # print(f"Decrypted key: {decrypted_key}")

    # # msg = int(input("Enter a message: "))
    # msg = key_byte_to_int(sym_key)
    # C1, C2 = elgamal_encrypt(msg, g, pairing, public_key, q)
    # print("C1 =", C1)
    # print("C2 =", C2)
    # # # Decrypt the message
    # msg_decrypted = elgamal_decrypt(C1, C2, pairing, private_key, g, q)
    # print(f"Decrypted message: {key_int_to_byte(msg_decrypted)}")
    # # # Check that the decrypted message is the same as the original
    # assert msg == msg_decrypted