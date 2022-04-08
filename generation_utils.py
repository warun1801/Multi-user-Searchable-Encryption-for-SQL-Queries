from pypbc import Element, Pairing, Parameters, Zr, G1, G2, GT, get_random_prime
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning) 

"""
Functions available
['Element', 'G1', 'G2', 'GT', 'PBC_EC_Compressed',
 'Pairing', 'Parameters', 'Zr', '__doc__', '__file__',
 '__loader__', '__name__', '__package__', '__spec__',
 'get_random', 'get_random_prime', 'set_point_format_compressed',
 'set_point_format_uncompressed']

Element - Class
Pairing - Class
Parameters - Class
Zr - int??
get_random_prime - Function, parameters : int (most likely the no.of bits)
set_point_format_compressed - Function, parameters : None
set_point_format_uncompressed - Function, parameters : None
"""

# def test_bls():
#     stored_params = """type a
#     q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
#     h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
#     r 730750818665451621361119245571504901405976559617
#     exp2 159
#     exp1 107
#     sign1 1
#     sign0 1
#     """


def setup(k):
    # Generate the parameters
    param = Parameters(qbits=4*k, rbits=k)
    ls = list(str(param).split("\n"))
    
    # this is actually r
    q = int(ls[3].split(" ")[1])
    pairing = Pairing(param)
    g = Element.random(pairing, G1)

    private_key = Element.random(pairing, Zr)
    public_key = Element(pairing, G1, value=g**private_key)

    print("Private:", private_key)
    print("Public:", public_key)

    print("q:", q)
    print("g", g)
    
    # def hash1(message):
    #     return Element.from_hash(pairing, G1, str(message))

    # def hash2(element):
    #     return Element.from_hash(pairing, Zr, str(element))

    # def hash3(message):
    #     return Element.from_hash(pairing, Zr, str(message))
    
    # return {
    #         "q": q,
    #         "e": pairing,
    #         "g": str(g),
    #         "h1": hash1,
    #         "h2": hash2,
    #         "h3": hash3
    #         } #params
    

def key_gen(params):
    pairing = params["e"]
    g = params["g"]
    
    private_key = Element.random(pairing, Zr)
    public_key = Element(pairing, G1, value=g**private_key)
    
    print("q = ", params["q"])
    print("g =", g)
    print("public_key =", public_key)
    print("private_key =", private_key)

    return (public_key, private_key)

def main():
    params = setup(1024)
    # keys = key_gen(params)
    

if __name__ == '__main__':
    main()