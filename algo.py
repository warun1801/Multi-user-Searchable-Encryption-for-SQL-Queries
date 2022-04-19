import pypbc
from pypbc import Parameters, Pairing, Element, G1, G2, GT, Zr
from inspect import signature
"""
Functions available
['Element', 'G1', 'G2', 'GT', 'PBC_EC_Compressed',
 'Pairing', 'Parameters', 'Zr', '__doc__', '__file__',
 '__loader__', '__name__', '__package__', '__spec__',
 'get_random', 'get_random_prime', 'set_point_format_compressed',
 'set_point_format_uncompressed']
"""
"""
Element - Class
Pairing - Class
Parameters - Class
Zr - int??
get_random_prime - Function, parameters : int (most likely the no.of bits)
set_point_format_compressed - Function, parameters : None
set_point_format_uncompressed - Function, parameters : None
"""



def setup(k):
    # Generate the parameters
    q = pypbc.get_random_prime(k)
    print("q = ", q)
    # pypbc.Zr = q
    # pairing_to_use =  pypbc.Pairing()
    # print(pairing_to_use)
    # print(dir(pypbc.Element))
    # x = pypbc.Element
    # print(x)
    param = Parameters(qbits=4*k,rbits=k)
    print(param)
    pairing = Pairing(param)
    P = Element.random(pairing, G1)
    Q = Element.random(pairing, G2)
    r = Element.random(pairing, Zr)
    e = pairing.apply(P, Q)
    print("params =", param)
    print("pairing =", str(pairing))
    print("P =", str(P))
    print("Q =", str(Q))
    print("r =", str(r))
    PP = Element(pairing, G1, value=str(P))
    print("PP =", str(PP))
    print("Zr =", pypbc.Zr)
    print("e =", str(e))

    def hash1(message):
        return Element.from_hash(pairing, G1, str(message))

    def hash2(element):
        return Element.from_hash(pairing, Zr, str(element))

    def hash3(message):
        return Element.from_hash(pairing, Zr, str(message))

    # print(hash2(P))
    return {"q":r,"e":pairing,"g":P,"H1": hash1,"H2": hash2, "H3": hash3} #params

def KeyGen(params):
    pairing = params['e']
    g = params["g"]
    private_key = Element.random(pairing, Zr)
    public_key = Element(pairing, G1, value=g**private_key)
    print("public_key =", public_key)
    print("private_key =", private_key)

def test_bls():
    stored_params = """type a
    q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
    h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
    r 730750818665451621361119245571504901405976559617
    exp2 159
    exp1 107
    sign1 1
    sign0 1
    """

    # this is a test for the BLS short signature system
    params = Parameters(param_string=stored_params)
    pairing = Pairing(params)

    # build the common parameter g
    g = Element.random(pairing, G2)
    # print("g =", g)

    # build the public and private keys
    private_key = Element.random(pairing, Zr)
    public_key = Element(pairing, G2, value=g**private_key)
    print("public_key =", public_key)
    print("private_key =", private_key)

    # # set the magic hash value
    hash_value = Element.from_hash(pairing, G1, "message")
    print("hash_value =", hash_value)

    # # create the signature
    # signature = hash_value**private_key

    # # build the temps
    # temp1 = Element(pairing, GT)
    # temp2 = Element(pairing, GT) 

    # # fill temp1
    # temp1 = pairing.apply(signature, g)

    # #fill temp2
    # temp2 = pairing.apply(hash_value, public_key)

    # # and again...
    # temp1 = pairing.apply(signature, g)

    # # compare
    # self.assertEqual(temp1 == temp2, True)

    # # compare to random signature
    # rnd = Element.random(pairing, G1)
    # temp1 = pairing.apply(rnd, g)

    # # compare
    # self.assertEqual(temp1 == temp2, False)

def main():
    setup(4)
    # test_bls()

if __name__ == '__main__':
    main()