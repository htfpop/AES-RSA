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
        self.pub_name =  name + '.pub'
        self.priv_name = name + '.priv'
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.modulus = modulus

    def set_pub(self, pub_key): self.pub_key = pub_key
    def get_pub(self): return self.pub_key

    def set_priv(self, priv_key): self.priv_key = priv_key
    def get_priv(self): return self.priv_key

    def set_mod(self, modulus): self.modulus = modulus
    def get_mod(self): return self.modulus


def key_IO(rsa: RSA):
    """
    This function handles the IO for generating <name>.pub and <name>.priv
    NOTICE - Key pairs will be in BASE64
    :param rsa: RSA instance that has been populated with both RSA Public / Private / Modulus instance
    :return: None
    """
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
    This function generates RSA public and private keys
    NOTICE - Public exponent is set to a static integer - 65537
             ALL private/public keys pairs will be stored as base64
    :param rsa: RSA instance
    :return: None
    """
    status = FAILURE
    p1 = None
    p2 = None

    # Attempt to generate 2 primes (p / q) and ensure they are not the same
    while p1 is None or p2 is None or status is not SUCCESS:
        p1 = gen_prime()
        p2 = gen_prime()

        if p1 != p2:
            status = SUCCESS

    #print(f'[p1]: {p1}')
    #print(f'[p2]: {p2}')

    # calculate RSA Modulus
    n = p1 * p2

    # calculate RSA Totient (p-1)(q-1)
    totient = (p1 - 1) * (p2 - 1)

    # Set static public exponent 2^16 + 1
    e = 65537

    # Calculate modular inverse such that e * d = 1 Mod( Phi (n) )
    d = modinv(e, totient)

    #print(f'[private] = {d}')
    #print(f'[mod] = {n}')

    # Encode RSA Public Exponent as Base64
    e_64 = base64.b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big'))
    #print(f'[e64] = {e_64}')

    # Encode RSA Private Key as Base64
    priv_64 = base64.b64encode(d.to_bytes((d.bit_length() + 7) // 8, byteorder='big'))
    #print(f'[e64] = {pub_64}')

    # Encode RSA Modulus as Base64
    mod_64 = base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))
    #print(f'[e64] = {mod_64}')

    # Set all variables to respective members in our RSA instance
    rsa.set_pub(e_64)
    rsa.set_priv(priv_64)
    rsa.set_mod(mod_64)

    #test1 = int.from_bytes(base64.b64decode(rsa.get_pub()), byteorder='big')
    #test2 = int.from_bytes(base64.b64decode(rsa.get_priv()), byteorder='big')
    #test3 = int.from_bytes(base64.b64decode(rsa.get_mod()), byteorder='big')

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
    """
    This function utilizes the Rabin-Miller primality test on a randomly generated number
    to test for probable primes / composite numbers.
    :return: Probable Prime number
    """
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
    <WARN> This algorithm implementation follows the following wikipedia page <WARN>
    <WARN> Code has been commented to demonstrate understanding               <WARN>
    Pseudocode Algorithm origination: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    :param n: integer to test for primality
    :param tests: number of test to perform
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


if __name__ == '__main__':
    rsa_instance = parse_args()
    gen_key(rsa_instance)
    key_IO(rsa_instance)
    debug(rsa_instance)
