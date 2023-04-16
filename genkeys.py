import base64
import os
import sys
import random
import base64

RSA_MAX_SIZE_BYTES = 128
COMPOSITE_NUM = 0xDEADDEAD
SUCCESS = 0xCAFECAFE
FAILURE = 0xDEADBEEF


class RSA:
    def __init__(self, name=None, pub_key=None, priv_key=None, modulus=None):
        self.name = name
        self.pub_name = 'keys\\' + name + '.pub'  # test only
        self.priv_name = 'keys\\' + name + '.priv'  # test only
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.modulus = modulus

    def get_pub(self): return self.pub_key

    def get_pub_str(self): return str(self.pub_key)

    def set_pub(self, pub_key): self.pub_key = pub_key

    def get_priv(self): return self.priv_key

    def set_priv(self, priv_key): self.priv_key = priv_key

    def get_priv_str(self): return self.priv_key

    def set_mod(self, modulus): self.modulus = modulus

    def get_mod(self): return self.modulus


def main():
    print(f'Inside genkeys.py')


def key_IO(rsa: RSA):
    if rsa.pub_key is None:
        print(f'[ERROR]: RSA Public key is NULL!')
        exit(-1)

    if rsa.priv_key is None:
        print(f'[ERROR]: RSA Private key is NULL!')
        exit(-1)

    else:
        with open(rsa.pub_name, 'wb') as pub:
            pub.write("--- RSA PUBLIC KEY ---\n".encode())
            pub.write(rsa.get_pub())
            pub.write("\n".encode())
            pub.write("--- RSA MODULUS ---\n".encode())
            pub.write(rsa.get_mod())
            pub.close()

        with open(rsa.priv_name, 'wb') as priv:
            priv.write("--- RSA PRIVATE KEY ---\n".encode())
            priv.write(rsa.get_priv())
            priv.write("\n".encode())
            priv.write("--- RSA MODULUS ---\n".encode())
            priv.write(rsa.get_mod())
            priv.close()


def gen_key(rsa: RSA):
    """
    Utilizes Miller-Rabin Primality test for generating Prime numbers
    :param rsa: RSA instance
    :return: None
    """
    status = FAILURE
    p1 = None
    p2 = None

    while p1 is None or p2 is None or status is not SUCCESS:
        p1 = gen_prime()
        p2 = gen_prime()

        if p1 != p2:
            status = SUCCESS

    print(f'[p1]: {p1}')
    print(f'[p2]: {p2}')

    n = p1 * p2
    totient = (p1 - 1) * (p2 - 1)
    e = 65537
    d = modinv(e, totient)

    print(f'[private] = {d}')
    print(f'[mod] = {n}')

    e_64 = base64.b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big'))
    print(f'[e64] = {e_64}')

    pub_64 = base64.b64encode(d.to_bytes((d.bit_length() + 7) // 8, byteorder='big'))
    print(f'[e64] = {pub_64}')

    mod_64 = base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))
    print(f'[e64] = {mod_64}')

    rsa.set_pub(e_64)
    rsa.set_priv(pub_64)
    rsa.set_mod(mod_64)

    test1 = int.from_bytes(base64.b64decode(rsa.get_pub()), byteorder='big')
    test2 = int.from_bytes(base64.b64decode(rsa.get_priv()), byteorder='big')
    test3 = int.from_bytes(base64.b64decode(rsa.get_mod()), byteorder='big')

    print(test1 == e)
    print(test2 == d)
    print(test3 == n)

    # rsa.set_pub(bytearray(e))

    # rsa.set_priv(bytearray(d))

    # rsa.set_mod(bytearray(n))

    """
    test = "Cryptography, or cryptology, is the practice and study of techniques for secure\ncommunication in the " \
           "presence of adversarial behavior."
    myint = int.from_bytes(test.encode(), byteorder='big')
    print(myint)

    enc = pow(myint, e, n)
    print(f'Enc: {enc}')

    dec = pow(enc, d, n)
    print(f'dec: {dec}')

    byte_string = dec.to_bytes((dec.bit_length() + 7) // 8, byteorder='big')
    message = byte_string.decode(encoding='utf-8', errors='ignore')
    print(message)



    for x in range(100):
        p = gen_prime()
        print(f'P[{x}] = {p}')
"""


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def gen_prime():
    candidate = None
    status = FAILURE

    while status is not SUCCESS:
        candidate = int.from_bytes(os.urandom(RSA_MAX_SIZE_BYTES), byteorder="big")
        status = Miller_Rabin(candidate, 1024)

    return candidate


def parse_args():
    args = sys.argv

    if len(args) < 2:
        print(f'[ERROR]: Not enough arguments.\nUSAGE: python genkeys.py <name>\nExiting now')
        exit(-1)

    if len(args) > 2:
        print(f'[ERROR]: Too many arguments.\nUSAGE: python genkeys.py <name>\nExiting now')
        exit(-1)

    return RSA(args[1])


def debug(rsa_instance):
    public = int.from_bytes(base64.b64decode(rsa_instance.get_pub()), byteorder='big')
    private = int.from_bytes(base64.b64decode(rsa_instance.get_priv()), byteorder='big')
    mod = int.from_bytes(base64.b64decode(rsa_instance.get_mod()), byteorder='big')
    print(f'Public: {public}')
    print(f'Private: {private}')
    print(f'mod: {mod}')


def Miller_Rabin(n: int, tests):
    """
    Miller-Rabin Primality test
    Pseudocode Algorithm origination: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    :return: status - COMPOSITE_NUM / FAILURE / SUCCESS
    """

    y = 0
    exponent = 0
    remainder = 0
    status = FAILURE
    even = n - 1

    # if original number is even, it is a composite number
    if n % 2 == 0:
        return COMPOSITE_NUM

    # factor out powers of 2 and increment exponent by 1
    while even % 2 == 0:
        exponent = exponent + 1  # increase powers of 2 as long as its even
        even >>= 1  # divide (n-1) by 2 for each while iteration until getting an odd number

    # Compute remainder = (n - 1) / 2 ^ s
    # NOTICE - USE INTEGER DIVISION. "/" for large numbers performs float division
    remainder = (n - 1) // pow(2, exponent)

    # sanity check (n - 1) = 2^exponent * remainder
    if pow(2, exponent) * remainder != n - 1:
        return FAILURE

    # perform regression tests to ensure confidence that the number is prime
    for i in range(tests):
        # choose number at random
        a = random.randrange(2, n - 2)

        # compute random co-integer within same n space
        x = pow(a, remainder, n)  # a ^ remainder mod n

        for j in range(exponent):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n - 1:
                return COMPOSITE_NUM
            x = y
        if y != 1:
            return COMPOSITE_NUM

    return SUCCESS

"""
def b64test():
    p = 127957588420386745086765575457872908695233629600310278052584039952300843395144810957925840258213116622068179970520791734746605213596186686820952083462451220874711108015759356361555132701379671952110421588410952801109110297441563260418099145314264706792960918515708961753189586733887264052823206158872301972001
    bytes = p.to_bytes((p.bit_length() + 7) // 8, byteorder='big')
    encoded = base64.b64encode(bytes)

    with open('test\\mytest.txt', 'w') as f:
        f.write(encoded.decode())
        f.close()

    with open('test\\mytest.txt', 'r') as i:
        val = i.read()
        new = base64.b64decode(val)
        i.close()

    newval = int.from_bytes(new, byteorder='big')
    print(newval == p)
"""

if __name__ == '__main__':
    #b64test()
    rsa_instance = parse_args()
    gen_key(rsa_instance)
    key_IO(rsa_instance)
    debug(rsa_instance)
