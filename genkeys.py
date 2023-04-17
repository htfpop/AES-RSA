""" **************************************************************
* Programmer : Christopher K. Leung (2965-7518-69)               *
* Course ID  : CSCI531 - Applied Cryptography                    *
* Due Date   : March 16, 2023                                    *
* Project    : RSA-AES Implementation                            *
* Purpose    : This file generates RSA-1024 Public/Private keys  *
*****************************************************************"""

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
        try:
            with open(rsa.pub_name, 'wb') as pub:
                pub.write("--- RSA PUBLIC KEY ---\n".encode())
                pub.write(rsa.get_pub())
                pub.write("\n".encode())
                pub.write("--- RSA MODULUS ---\n".encode())
                pub.write(rsa.get_mod())
                pub.close()
        except IOError:
            print(f'[IO ERROR]: Could not open {rsa.pub_name} to write to. Please Try again.\nExiting')
            exit(-1)

        try:
            with open(rsa.priv_name, 'wb') as priv:
                priv.write("--- RSA PRIVATE KEY ---\n".encode())
                priv.write(rsa.get_priv())
                priv.write("\n".encode())
                priv.write("--- RSA MODULUS ---\n".encode())
                priv.write(rsa.get_mod())
                priv.close()
        except IOError:
            print(f'[IO ERROR]: Could not open {rsa.priv_name} to write to. Please Try again.\nExiting')
            exit(-1)


def check_params(p1, p2, totient, d, e):
    """
    Determine if RSA parameters meet certain specifications:
        - prime numbers are not 1024 bits in length
        - P1 / P2 cannot be the same integer
        - e * d mod(phi(n)) == 1
        - totient bit length should be less than 2048 (since we are using 1024 bit prime numbers)
    :param p1: Prime 1
    :param p2: Prime 2
    :param totient: (p1 - 1) (p2 - 1)
    :param d: - Private exponent
    :param e: - Public Exponent
    :return: True if parameters meet conditions, else False
    """
    if (p1.bit_length() != 1024): return False
    if (p2.bit_length() != 1024): return False
    if( p1 == p2 ): return False
    if( (e * d) % totient != 1): return False
    if( totient.bit_length() > 2048 ): return False

    return True

def gen_key(rsa: RSA):
    """
    This function generates RSA public and private keys
    NOTICE - Public exponent is set to a static integer - 65537
             ALL private/public keys pairs will be stored as base64
    :param rsa: RSA instance
    :return: None
    """
    valid_params = False
    status = FAILURE
    p1 = None
    p2 = None
    d = None

    while not valid_params:
        # Attempt to generate 2 primes (p / q) and ensure they are not the same
        p1 = gen_prime()
        p2 = gen_prime()

        # calculate RSA Modulus
        n = p1 * p2

        # calculate RSA Totient (p-1)(q-1)
        totient = (p1 - 1) * (p2 - 1)

        # Set static public exponent 2^16 + 1
        e = 65537

        # Calculate modular inverse such that e * d = 1 Mod( Phi (n) )
        d = modinv(e, totient)
        #print(d)

        # Check for RSA Valid Parameters
        valid_params = check_params(p1, p2, totient, d, e)

    if valid_params:
        # Encode RSA Public Exponent as Base64
        e_64 = base64.b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big'))

        # Encode RSA Private Key as Base64
        priv_64 = base64.b64encode(d.to_bytes((d.bit_length() + 7) // 8, byteorder='big'))

        # Encode RSA Modulus as Base64
        mod_64 = base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))

        # Set all variables to respective members in our RSA instance
        rsa.set_pub(e_64)
        rsa.set_priv(priv_64)
        rsa.set_mod(mod_64)
    else:
        print(f'Could not generate RSA Parameters')


def modinv(a, m):
    """
    Wrapper function for Extended Eucledian Algorithm
    Using Bezout's identity such that ax + by = gcd(a,b)
    <WARN> This algorithm implementation follows the following wikipedia page <WARN>
    <WARN> Code has been commented to demonstrate understanding               <WARN>
    <WARN> This comment is to mitigate USC academic dishonesty                <WARN>
    Wrapper taken from here: https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    Extended GCD Derived from pseudocode here: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    :param a: Public Exponent
    :param m: Totient
    :return: Coprime integer that fulfills E*D == 1 mod (phi(n))
    """

    #call extended eucledian algorithm to find Bezout's coefficients and GCD(a,b)
    g, x, y = extended_eucledian(a, m)

    # raise exception if no remainder is found else, take bezout's coefficient modded by the totient
    if g != 1:
        raise Exception('modular inverse does not exist. Please re-run genkeys.py')
    else:
        return x % m


def extended_eucledian(a,b):
    """
    Extended Eucledian algorithm for calculating modular inverses - NON RECURSIVE
    Using Bezout's identity such that ax + by = gcd(a,b)
    <WARN> This algorithm implementation follows the following wikipedia page <WARN>
    <WARN> Code has been commented to demonstrate understanding               <WARN>
    <WARN> This comment is to mitigate USC academic dishonesty                <WARN>
    Wrapper taken from here: https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    Extended GCD Derived from pseudocode here: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    :param a: Public Exponent
    :param b: Totient
    :return: Bezout's coefficients and greatest common divisor
    """

    # Variable initialization for keeping track of previous remainder and coefficients
    old_r = a
    old_s = 1
    old_t = 0
    r = b
    s = 0
    t = 1

    # continuously divide remainder by dividend until reaching 1 or 0
    # compute current/previous remainders, and bezout's coefficients such that we obtain s coefficient that will be
    # modded by the modulus in modinv() function
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    # if bezout's coefficient of interest is negative, reverse polarity by adding totient
    if old_s < 0:
        old_s += b

    return old_r, old_s, old_t


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
        status = Miller_Rabin(candidate, 256)

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

def Miller_Rabin(n: int, tests):
    """
    Miller-Rabin Primality test
    <WARN> This algorithm implementation follows the following wikipedia page <WARN>
    <WARN> Code has been commented to demonstrate understanding               <WARN>
    <WARN> This comment is to mitigate USC academic dishonesty                <WARN>
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

        # calculate the squared modulo (exponent) times. if y == 1, x != 1 and x != n-1 we can
        # safely assume that this number is composite. After, store the value of y into x for processing
        # for the next iteration.
        for j in range(exponent):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n - 1:
                return COMPOSITE_NUM
            x = y

        # at the end of (exponent) iterations, if y should be == 1. If not, return composite number.
        if y != 1:
            return COMPOSITE_NUM

    # if the above holds true, we have a PROBABLE PRIME.
    return SUCCESS


if __name__ == '__main__':
    print("-----------------------------------")
    print("CSCI-531 RSA-1024 Key Generation")
    print("-----------------------------------")

    rsa_instance = parse_args()
    gen_key(rsa_instance)
    key_IO(rsa_instance)

    if rsa_instance.pub_key is not None and rsa_instance.priv_key is not None and rsa_instance.modulus is not None:
        print(f'Successfully Generated {rsa_instance.pub_name}')
        print(f'Successfully Generated {rsa_instance.priv_name}')
