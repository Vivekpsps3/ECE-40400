import sys
from BitVector import *

class AES():
    def __init__(self, keyfile:str) -> None:
        pass

    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        pass

    def decrypt(self, ciphertext:str, decrypted:str) -> None:
        pass

if __name__ == "__main__":
    task = sys.argv[1]
    input_file = sys.argv[2]
    key_file = sys.argv[3]
    output_file = sys.argv[4]

    cipher = AES(keyfile=key_file)

    if task == "-e":
        cipher.encrypt(plaintext = input_file, ciphertext = output_file)
    elif task == "-d":
        cipher.decrypt(ciphertext = input_file, decrypted = output_file)
    else:
        sys.exit("Incorrect CLI arguments. Please use -e or -d.")
