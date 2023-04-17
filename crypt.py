""" **************************************************************
* Programmer : Christopher K. Leung (2965-7518-69)               *
* Course ID  : CSCI531 - Applied Cryptography                    *
* Due Date   : March 16, 2023                                    *
* Project    : RSA-1024 / AES-128 Implementation                 *
* Purpose    : This file handles encryption and decryption using *
               AES-128 ECB and encrypting/decrypting the AES red *
               key with RSA-1024                                 *
*****************************************************************"""
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


def key_IO(crypt_instance: Crypt):
    """
    Perform Cryptographic Key Input/Output processing
    :param crypt_instance: Object storing input / output files
    :return: none
    """
    # error handling
    if crypt_instance.key_file is None:
        print(f'[ERROR]: Crypto key is NULL!')
        exit(-1)

    # Parse encrypted file
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
    """
    Perform AES-128 ECB encryption
    :param crypt_inst: Object storing red key, and file I/O
    :return: None
    """

    # Block size should be 128 bytes
    padder = padding.PKCS7(128).padder()

    # obtain input all plaintext data and use red-key to encrypt
    key = crypt_inst.get_AES_red_key()
    infile = open(crypt_inst.get_input_file(), 'r')
    data = bytes(infile.read(), 'utf-8')
    infile.close()

    try:
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
    except ValueError:
        print(f'[VALUE ERROR]: Invalid AES-128 Key. Have you used the right key?\nExiting.')
        exit(-1)

    encryptor = cipher.encryptor()

    padder_data = padder.update(data)
    padder_data += padder.finalize()

    ct = encryptor.update(padder_data) + encryptor.finalize()

    # write to output file AES-128 black key and ciphertext
    try:
        with open(crypt_instance.get_output_file(), 'wb') as outfile:
            outfile.write("--- AES BLACK KEY ---\n".encode())
            outfile.write(base64.b64encode(crypt_inst.get_AES_black_key()))
            outfile.write("\n".encode())
            outfile.write("--- CIPHERTEXT ---\n".encode())
            outfile.write(base64.b64encode(ct))
            outfile.close()
    except IOError:
        print(f'[IO ERROR]: Could not open {crypt_instance.output_file} to write to. Please Try again.\nExiting')
        exit(-1)

def decrypt(crypt_inst: Crypt):
    """
    Perform AES-128 ECB decryption
    :param crypt_inst: object that stores AES-Black Key and Ciphertext
    :return: None
    """

    # get AES red key used for decrypting ciphertext
    key = crypt_inst.get_AES_red_key()
    ct = crypt_inst.get_ct()
    unpadder = padding.PKCS7(128).unpadder()

    try:
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
    except ValueError:
        print(f'[VALUE ERROR]: Invalid AES-128 Key. Have you used the right key?\nExiting.')
        exit(-1)

    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    unpadderdata = unpadder.update(pt)
    unpadderdata += unpadder.finalize()

    # write to output file
    try:
        outfile = open(crypt_inst.get_output_file(), 'wb')
        outfile.write(unpadderdata)
        outfile.close()
    except IOError:
        print(f'[IO ERROR]: Could not open {crypt_instance.output_file} to write to. Please Try again.\nExiting')
        exit(-1)


def gen_AES_key(crypt_instance):
    """
    Generate AES-128 ECB Red key
    :param crypt_instance: object that stores AES data
    :return: None
    """
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


def retrieve_AES_key(crypt_instance):
    """
    Retrieve AES Black key, then unwrap using RSA-1024
    :param crypt_instance: Object storage
    :return: None
    """
    try:
        with open(crypt_instance.get_input_file(), 'rb') as infile:
            infile.readline()  # read AES Black Key Header
            crypt_instance.set_AES_black_key(base64.b64decode(infile.readline()))
            infile.readline()  # read CT Header
            crypt_instance.set_ct(base64.b64decode(infile.readline()))
            infile.close()
    except IOError:
        print(f'[IO ERROR]: Could not open {crypt_instance.input_file} to read from. Please ensure path is correct.\nExiting')
        exit(-1)

    black_key = crypt_instance.get_AES_black_key()
    black_key_int = int.from_bytes(black_key, byteorder='big')

    rsa_key = int.from_bytes(crypt_instance.get_key(), byteorder='big')
    rsa_modulus = int.from_bytes(crypt_instance.get_modulus(), byteorder='big')

    aes_red_key_int = pow(black_key_int, rsa_key, rsa_modulus)

    crypt_instance.set_AES_red_key(aes_red_key_int.to_bytes((aes_red_key_int.bit_length() + 7) // 8, byteorder='big'))


if __name__ == '__main__':
    print("------------------------------------------")
    print("CSCI-531 RSA-1024 / AES-128 Implementation")
    print("------------------------------------------")

    crypt_instance = parse_args()
    key_IO(crypt_instance)

    if crypt_instance.get_mode() == ENCRYPT:
        print(f'Attempting to encrypt \"{crypt_instance.input_file}\"')
        gen_AES_key(crypt_instance)
        encrypt(crypt_instance)
        print(f'Successfully generated \"{crypt_instance.output_file}\"')
    else:
        print(f'Attempting to decrypt \"{crypt_instance.input_file}\"')
        retrieve_AES_key(crypt_instance)
        decrypt(crypt_instance)
        print(f'Successfully generated \"{crypt_instance.output_file}\"')
