import base64
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

RSA_MAX_SIZE_BYTES = 128
CRYPT_MAX_ARGS = 5
ENCRYPT = 0xBEEF4DAD
DECRYPT = 0xCAFECAFE
MODE_ERROR = 0xDEADBEEF


class Crypt:
    def __init__(self, mode=None, key_file=None, key=None, input_file=None, output_file=None):
        self.mode = mode
        self.key_file = key_file
        self.key = key
        self.input_file = input_file
        self.output_file = output_file

    def get_mode(self): return self.mode

    def get_key_file(self): return self.key_file

    def get_key(self): return self.key

    def get_input_file(self): return self.input_file

    def get_output_file(self): return self.output_file

    def set_mode(self, mode): self.mode = mode

    def set_key_file(self, key_file): self.key_file = key_file

    def set_key(self, key): self.key = key

    def set_input_file(self, input_file): self.input_file = input_file

    def set_output_file(self, output_file): self.output_file = output_file

    def print_key(self): return ' '.join('{:02x}'.format(x) for x in self.get_key())

    def __str__(self):
        s = '[MODE]: {0}\n' \
            '[KEY_FILE]: {1}\n' \
            '[KEY]: {2}\n' \
            '[INPUT_FILE]: {3}\n' \
            '[OUTPUT_FILE]: {4}\n' \
            .format(hex(self.get_mode()), self.get_key_file(), self.print_key(), self.get_input_file(),
                    self.get_output_file())
        return s


"""
        return print(f'[MODE]: {self.get_mode()}\n'
                     f'[KEY_FILE]: {self.get_key_file()}\n'
                     f'[KEY]: {self.get_key()}\n'
                     f'[INPUT_FILE]: {self.get_input_file()}\n'
                     f'[OUTPUT_FILE]: {self.get_output_file()}\n')
"""


def main():
    print(f'Inside crypt.py\r\n')


def key_IO(crypt_instance: Crypt):
    if crypt_instance.key_file is None:
        print(f'[ERROR]: Crypto key is NULL!')
        exit(-1)

    else:
        try:
            with open(crypt_instance.key_file, 'rb') as key:
                crypt_instance.set_key(base64.b64decode(key.read()))
                key.close()
        except IOError:
            print(f'[ERROR]: IO Error. Could not find {crypt_instance.key_file} in files.\nExiting.')
            exit(-1)


def parse_args():
    args = sys.argv
    mode = MODE_ERROR

    if len(args) < CRYPT_MAX_ARGS:
        print(f'[ERROR]: Not enough arguments.\nUSAGE: python crypt.py <-e/-d> <priv/pub key> <file to '
              f'encrypt/decrypt> <output file>\nExiting now')
        exit(-1)

    if len(args) > CRYPT_MAX_ARGS:
        print(f'[ERROR]: Too many arguments.\nUSAGE: python crypt.py <-e/-d> <priv/pub key> <file to '
              f'encrypt/decrypt> <output file>\nExiting now')
        exit(-1)

    if args[1] == '-e':
        mode = ENCRYPT
    elif args[1] == '-d':
        mode = DECRYPT
    else:
        mode = MODE_ERROR

    if mode == MODE_ERROR:
        print(f'[ERROR]: INVALID MODE OF OPERATION. Please choose ENCRYPT (-e) or DECRYPT (-d)\n'
              f'USAGE: python crypt.py <-e/-d> <priv/pub key> <file to encrypt/decrypt> <output file>\n'
              f'Exiting now')
        exit(-1)

    return Crypt(mode=mode, key_file=args[2], input_file=args[3], output_file=args[4])


def encrypt(crypt_inst: Crypt):
    padder = padding.PKCS7(128).padder()
    unpadder = padding.PKCS7(128).unpadder()
    key = os.urandom(16)  # 128
    infile = open('test/secret.txt', 'r')
    data = bytes(infile.read(), 'utf-8')
    infile.close()
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    padder_data = padder.update(data)
    padder_data += padder.finalize()

    ct = encryptor.update(padder_data) + encryptor.finalize()

    pt = decryptor.update(ct) + decryptor.finalize()
    print(pt)

    unpadderdata = unpadder.update(pt)
    unpadderdata += unpadder.finalize()

    print(unpadderdata)

    outfile = open('test/outfile.txt', 'wb')
    outfile.write(unpadderdata)


if __name__ == '__main__':
    # main()
    crypt_instance = parse_args()
    key_IO(crypt_instance)
    print(f'---- instance of crypt----\r\n{crypt_instance}')
    encrypt(crypt_instance)
    # print(f'---- debug----')
    # crypt_instance.printpub()
