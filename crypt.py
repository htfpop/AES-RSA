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
    def __init__(self, mode=None, key_file=None, key=None, input_file=None, output_file=None,
                 modulus=None, AES_red_key=None, AES_black_key=None, ct=None, pt=None):
        self.mode = mode
        self.key_file = key_file
        self.key = key
        self.input_file = input_file
        self.output_file = output_file
        self.modulus = modulus
        self.AES_red_key = AES_red_key
        self.AES_black_key = AES_black_key
        self.ct = ct
        self.pt = pt

    def set_ct(self, ct): self.ct = ct

    def get_ct(self): return self.ct

    def set_pt(self, pt): self.pt = pt

    def get_pt(self): return self.pt
    def set_mode(self, mode): self.mode = mode

    def get_mode(self): return self.mode

    def set_key_file(self, key_file): self.key_file = key_file

    def get_key_file(self): return self.key_file

    def set_key(self, key): self.key = key

    def get_key(self): return self.key

    def set_input_file(self, input_file): self.input_file = input_file

    def get_input_file(self): return self.input_file

    def set_output_file(self, output_file): self.output_file = output_file

    def get_output_file(self): return self.output_file

    def set_modulus(self, modulus): self.modulus = modulus

    def get_modulus(self): return self.modulus

    def set_AES_red_key(self, AES_red_key): self.AES_red_key = AES_red_key

    def get_AES_red_key(self): return self.AES_red_key

    def set_AES_black_key(self, AES_black_key): self.AES_black_key = AES_black_key

    def get_AES_black_key(self): return self.AES_black_key

    def __str__(self):
        s = '[MODE]: {0}\n' \
            '[KEY_FILE]: {1}\n' \
            '[KEY]: {2}\n' \
            '[INPUT_FILE]: {3}\n' \
            '[OUTPUT_FILE]: {4}\n' \
            .format(hex(self.get_mode()), self.get_key_file(), self.get_key(), self.get_input_file(),
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
                key.readline()  # read pub/priv header
                crypt_instance.set_key(base64.b64decode(key.readline()))
                key.readline()  # read modulus header
                crypt_instance.set_modulus(base64.b64decode(key.readline()))
                key.close()
        except IOError:
            print(f'[ERROR]: IO Error. Could not find {crypt_instance.key_file} in files.\nExiting.')
            exit(-1)

    print(int.from_bytes(crypt_instance.get_key(), byteorder='big'))
    print(int.from_bytes(crypt_instance.get_modulus(), byteorder='big'))


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

    key = crypt_inst.get_AES_red_key()
    infile = open(crypt_inst.get_input_file(), 'r')
    data = bytes(infile.read(), 'utf-8')
    infile.close()
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()

    padder_data = padder.update(data)
    padder_data += padder.finalize()

    ct = encryptor.update(padder_data) + encryptor.finalize()

    with open(crypt_instance.get_output_file(), 'wb') as outfile:
        outfile.write("--- AES BLACK KEY ---\n".encode())
        outfile.write(base64.b64encode(crypt_inst.get_AES_black_key()))
        outfile.write("\n".encode())
        outfile.write("--- CIPHERTEXT ---\n".encode())
        outfile.write(base64.b64encode(ct))
        outfile.close()


def decrypt(crypt_inst: Crypt):
    key = crypt_inst.get_AES_red_key()
    ct = crypt_inst.get_ct()
    unpadder = padding.PKCS7(128).unpadder()
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    print(pt)

    unpadderdata = unpadder.update(pt)
    unpadderdata += unpadder.finalize()

    print(unpadderdata.decode())

    outfile = open(crypt_inst.get_output_file(), 'wb')
    outfile.write(unpadderdata)
    outfile.close()


def gen_AES_key(crypt_instance):
    if crypt_instance.key is None:
        print(f'[ERROR]: RSA KEY FILE NOT FOUND. Exiting')
        exit(-1)

    key = os.urandom(16)  # 128

    red_key = int.from_bytes(key, byteorder='big')

    rsa_public_key = int.from_bytes(crypt_instance.get_key(), byteorder='big')
    rsa_modulus = int.from_bytes(crypt_instance.get_modulus(), byteorder='big')

    black_key = pow(red_key, rsa_public_key, rsa_modulus)

    black_key_bytes = black_key.to_bytes((black_key.bit_length() + 7) // 8, byteorder='big')

    crypt_instance.set_AES_red_key(key)
    crypt_instance.set_AES_black_key(black_key_bytes)

    print(f'[AES Red]: {crypt_instance.get_AES_red_key()}')
    print(f'[AES Black]: {crypt_instance.get_AES_black_key()}')
    print(f'[RSA Key]: {base64.b64encode(crypt_instance.get_key())}')
    print(f'[RSA Mod]: {base64.b64encode(crypt_instance.get_modulus())}')


def retrieve_AES_key(crypt_instance):
    with open(crypt_instance.get_input_file(), 'rb') as infile:
        infile.readline()  # read AES Black Key Header
        crypt_instance.set_AES_black_key(base64.b64decode(infile.readline()))
        infile.readline()  # read CT Header
        crypt_instance.set_ct(base64.b64decode(infile.readline()))
        infile.close()

    black_key = crypt_instance.get_AES_black_key()
    black_key_int = int.from_bytes(black_key, byteorder='big')

    rsa_key = int.from_bytes(crypt_instance.get_key(), byteorder='big')
    rsa_modulus = int.from_bytes(crypt_instance.get_modulus(), byteorder='big')

    aes_red_key_int = pow(black_key_int, rsa_key, rsa_modulus)

    crypt_instance.set_AES_red_key(aes_red_key_int.to_bytes((aes_red_key_int.bit_length() + 7) // 8, byteorder='big'))


if __name__ == '__main__':
    # main()
    crypt_instance = parse_args()
    key_IO(crypt_instance)
    print(f'---- instance of crypt----\r\n{crypt_instance}')
    if crypt_instance.get_mode() == ENCRYPT:
        gen_AES_key(crypt_instance)
        encrypt(crypt_instance)
    else:
        retrieve_AES_key(crypt_instance)
        decrypt(crypt_instance)
