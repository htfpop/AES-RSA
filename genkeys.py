import base64
import math
import os
import sys
import random
import sympy

RSA_MAX_SIZE_BYTES = 128
COMPOSITE_NUM = 0xDEADDEAD
SUCCESS = 0xCAFECAFE
FAILURE = 0xDEADBEEF


class RSA:
    def __init__(self, name=None, pub_key=None, priv_key=None):
        self.name = name
        # self.pub_name = name+'.pub'
        # self.priv_name = name+'.priv'
        self.pub_name = 'keys\\' + name + '.pub'  # test only
        self.priv_name = 'keys\\' + name + '.priv'  # test only
        self.pub_key: bytearray = pub_key
        self.priv_key: bytearray = priv_key

    def get_pub(self): return self.pub_key

    def get_pub_str(self): return str(self.pub_key)

    def set_pub(self, pub_key): self.pub_key = pub_key

    def get_priv(self): return self.priv_key

    def set_priv(self, priv_key): self.priv_key = priv_key

    def get_priv_str(self): return str(self.priv_key)


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
            pub.write(base64.b64encode(rsa.get_pub()))
            pub.close()

        with open(rsa.priv_name, 'wb') as priv:
            priv.write(base64.b64encode(rsa.get_priv()))
            priv.close()


def gen_key(rsa: RSA):
    """
    TESTING - need to implement Rabin-Miller primality test here
    :param rsa: RSA instance
    :return: None
    """
    rsa.set_priv(bytearray(os.urandom(RSA_MAX_SIZE_BYTES)))
    rsa.set_pub(os.urandom(RSA_MAX_SIZE_BYTES))


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
    print('Public: ' + ' '.join('{:02x}'.format(x) for x in rsa_instance.pub_key))
    print('Private: ' + ' '.join('{:02x}'.format(x) for x in rsa_instance.priv_key))


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
    remainder = (n-1) // pow(2, exponent)

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


def test():
    status = FAILURE
    num = 0
    carmichales = [561, 1105, 1729, 2465, 2821, 6601, 8911, 10585, 15841, 29341, 41041, 46657, 52633, 62745, 63973, 75361, 101101, 115921, 126217, 162401, 172081, 188461, 252601, 278545, 294409, 314821, 334153, 340561, 399001, 410041, 449065, 488881, 512461, 530881]

    for i in range(len(carmichales)):
        if Miller_Rabin(carmichales[i], 1024) == SUCCESS:
            print(f'FAILURE')

    print('done')
"""
    for x in range(50):
        #print(f'x:{x}')
        while status is not SUCCESS:
            num = int.from_bytes(os.urandom(128), byteorder="big")
            #print(f'Attempting: {num}')
            status = Miller_Rabin(num, 100)

        if not sympy.isprime(num):
            print(f'MISMATCH : {num}')
            break

        print(f'prime {num}')
        status = FAILURE
"""


def WTF():
    NUMBER = 16311308084892934973
    # NUMBER = 1234564598321548432154846513218461321498432118465132132184651321879846511
    test1 = NUMBER - 1  # same number but even
    test2 = NUMBER - 1  # same number but even
    test3 = NUMBER - 1  # same number but even

    # auto floor using //= ony check LSBit if 0/1 to determine odd/even
    print(f'[TEST1 VALUE START]: {test1} ')
    while test1 & 1 == 0:
        temp = test1 // 2
        test1 = temp
        print(f'[TEST1]: {test1}')

    print()

    # using % 2 to determine if odd/even
    print(f'[TEST2 VALUE START]: {test2} ')
    while test2 % 2 == 0:
        test2 = int(test2) / int(2)
        print(f'[TEST2]: {test2}')

    print()

    # USING SHIFT
    print(f'[TEST3 VALUE START]: {test3} ')
    while test3 % 2 == 0:
        test3 >>= 1
        print(f'[TEST3]: {test3}')


if __name__ == '__main__':
    test()
    # WTF()
    # rsa_instance = parse_args()
    # gen_key(rsa_instance)
    # key_IO(rsa_instance)
    # debug(rsa_instance)
