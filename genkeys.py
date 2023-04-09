import os
import sys

RSA_MAX_SIZE_BYTES = 128


class RSA:
    def __init__(self, name=None, pub_key=None, priv_key=None):
        self.name = name
        # self.pub_name = name+'.pub'
        # self.priv_name = name+'.priv'
        self.pub_name = 'keys\\' + name + '.pub'  # test only
        self.priv_name = 'keys\\' + name + '.priv'  # test only
        self.pub_key = pub_key
        self.priv_key = priv_key

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
        with open(rsa.pub_name, 'w') as pub:
            pub.write(rsa.get_pub_str())
            pub.close()

        with open(rsa.priv_name, 'w') as priv:
            priv.write(rsa.get_priv_str())
            priv.close()


def gen_key(rsa: RSA):
    """
    TESTING - need to implement Rabin-Miller primality test here
    :param rsa: RSA instance
    :return: None
    """
    rsa.set_priv(os.urandom(RSA_MAX_SIZE_BYTES))
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


if __name__ == '__main__':
    rsa_instance = parse_args()
    gen_key(rsa_instance)
    key_IO(rsa_instance)
