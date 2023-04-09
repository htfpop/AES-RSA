import os

RSA_MAX_SIZE_BYTES = 128


class RSA:
    def __init__(self, pub_key=None, priv_key=None):
        self.pub_key = pub_key
        self.priv_key = priv_key

    def get_pub(self): return self.pub_key
    def get_pub_str(self): return str(self.pub_key)

    def set_pub(self, pub_key): self.pub_key = pub_key

    def get_priv(self): return self.priv_key

    def set_priv(self, priv_key): self.priv_key = priv_key
    def get_priv_str(self): return str(self.priv_key)


def main():
    print(f'Inside crypt.py')


def key_IO(rsa: RSA):
    with open('keys\\Alice.pub', 'w') as pub:
        pub.write(rsa.get_pub_str())
        pub.close()

    with open('keys\\Alice.priv', 'w') as priv:
        priv.write(rsa.get_priv_str())
        priv.close()


def gen_key():
    priv_key = os.urandom(RSA_MAX_SIZE_BYTES)
    pub_key = os.urandom(RSA_MAX_SIZE_BYTES)
    return RSA(pub_key=pub_key, priv_key=priv_key)


if __name__ == '__main__':
    main()
    rsa_instance = gen_key()
    key_IO(rsa_instance)
