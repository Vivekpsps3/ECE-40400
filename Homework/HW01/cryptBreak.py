# Homework Number: HW01
# Name: Raghava Vivekananda Panchagnula
# ECN Login: rpanchag
# Due Date: 1/18/2024

from BitVector import *

#change the current working dir
import os
cd = os.path.dirname(os.path.abspath(__file__))
os.chdir(cd)

# Read the file
file_name = 'cipherText.txt'

def cryptbreak(file_name, key_bv):

    #bv = BitVector(filename = file_name)

    #Initialize variables
    BLOCKSIZE = 16
    # numbytes = BLOCKSIZE // 8
    # PassPhrase = "Hopes and dreams of a million years"
    # # Reduce the passphrase to a bit array of size BLOCKSIZE:
    # bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
    # for i in range(0,len(PassPhrase) // numbytes):
    #     textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
    #     bv_iv ^= BitVector( textstring = textstr )
    #shortening the passphrase step
    bv_iv = BitVector(intVal = 6966, size = 16)

    # Create a bitvector from the ciphertext hex string:
    file = open(file_name)
    encrypted_bv = BitVector( hexstring = file.read())
    file.close()

    with open(file_name, 'r') as file:
        file_read = file.read()
        encrypted_bv = BitVector(hexstring = file_read)

    #encrypted_bv = BitVector( hexstring = file.read())
    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )      

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^=  previous_decrypted_block
        previous_decrypted_block = temp
        bv ^=  key_bv
        msg_decrypted_bv += bv

    # Extract plaintext from the decrypted bitvector:    
    outputtext = msg_decrypted_bv.get_text_from_bitvector()                     #(c)
    return outputtext

def cryptbreak_wrapper(randInt):
    outputtext = cryptbreak(file_name, randInt)
    if 'Ferrari' in outputtext:
        print(outputtext)
        print(randInt)
        #return True
    #return False
    
if __name__ == '__main__':
    from multiprocessing import Pool
    from time import time
    start = time()

    #generate array of ints from 0 to 2^16
    #randInts = [i for i in range(0,2**16)]
    #answer found to be 1616 so test around that
    #randInts = [i for i in range(1600,1650)]
    randInts = [1614,1615,1616,1617]
    key_bvs = [BitVector(intVal = i, size = 16) for i in randInts]
    # for i in key_bvs:
    #     cryptbreak_wrapper(i)
    pool = Pool(processes=4)
    pool.imap_unordered(cryptbreak_wrapper, key_bvs)
    pool.close()
    pool.join()
    end = time()
    print(end - start)
    