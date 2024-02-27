# Homework Number: HW06
# Name: Raghava Vivekananda Panchagnula
# ECN Login: rpanchag
# Due Date: 2/27/2024

import sys
from BitVector import *
from solve_pRoot import *
from PrimeGenerator import *

e = 3


def find_gcd(a, b) -> int:
    while(b):
        a, b = b, a % b
    return abs(a)

def generate_keys() -> None:
    #generate p and q
    prime_gen = PrimeGenerator(bits=128)
    p = prime_gen.findPrime()
    q = prime_gen.findPrime()

    #check that the leftmost bits of p and q are 1
    p_bv = BitVector(intVal=p)
    q_bv = BitVector(intVal=q)
    while(p_bv[0] != 1 or q_bv[0] != 1 or p_bv[1] != 1 or q_bv[1] != 1):
        p = prime_gen.findPrime()
        q = prime_gen.findPrime()
        p_bv = BitVector(intVal=p)
        q_bv = BitVector(intVal=q)

    #check that p and q are not equal and that gcd(p-1, e) and gcd(q-1, e) are 1
    while(p == q or find_gcd(p-1, e) != 1 or find_gcd(q-1, e) != 1):
        p = prime_gen.findPrime()
        q = prime_gen.findPrime()

    return p,q

def encrypt(message, enc1, enc2, enc3, nFile):
    #open the files for writing
    cipher_text = [open(enc1, 'w'), open(enc2, 'w'), open(enc3, 'w')]
    n_file = open(nFile, 'w')

    #for each of the files...
    for i in range(3):
        #generate a new set of p, q, and n
        p,q = generate_keys()
        n = p * q
        #create the public and private keys
        # pubKey = [e,n]
        # bv_e = BitVector(intVal=e)
        # phi = (p-1)*(q-1)
        # bv_phi = BitVector(intVal=phi)
        # bv_e_i = bv_e.multiplicative_inverse(bv_phi)
        # e_i = bv_e_i.int_val()
        # d = e_i % phi
        # priKey = [d,n]
        #private key doesn't get used in this function but it's here for reference
        #write the n to the n file
        n_file.write(str(n) + "\n")
        #open the message file and read it in 128 bit blocks
        bv = BitVector(filename=message)
        while(bv.more_to_read):
            bitvec = bv.read_bits_from_file(128)
            bitvec.pad_from_right(128 - bitvec.length())
            bitvec.pad_from_left(128)
            #encrypt the block
            c = pow(bitvec.int_val(), e, n)
            bv_c = BitVector(intVal=c, size=256)
            #write the encrypted block to the file
            cipher_text[i].write(bv_c.get_bitvector_in_hex())
    #close and cleanup
    cipher_text[0].close()
    cipher_text[1].close()
    cipher_text[2].close()
    n_file.close()

def crt(bv1, bv2, bv3, N, n_list) -> int:
    #use the chinese remainder theorem to decrypt the block

    #calculate n1, n2, and n3 which are the product of all the n's except the current one
    n1 = n_list[1] * n_list[2]
    n2 = n_list[2] * n_list[0]
    n3 = n_list[0] * n_list[1]

    #calculate the modular multiplicative inverse of n1, n2, and n3
    bv_n1 = BitVector(intVal=n1)
    bv_n2 = BitVector(intVal=n2)
    bv_n3 = BitVector(intVal=n3)
    n1_inv = bv_n1.multiplicative_inverse(BitVector(intVal=n_list[0])).int_val()
    n2_inv = bv_n2.multiplicative_inverse(BitVector(intVal=n_list[1])).int_val()
    n3_inv = bv_n3.multiplicative_inverse(BitVector(intVal=n_list[2])).int_val()

    #calculate x, which is the decrypted block
    #x is the sum of the product of the encrypted block and the product of the n's and the modular multiplicative inverse of the n's
    x = (bv1 * n1 * n1_inv + bv2 * n2 * n2_inv + bv3 * n3 * n3_inv) % N

    return x

def crack(enc1, enc2, enc3, nFile, cracked):
    #open the file for writing
    cracked_file = open(cracked, 'w')

    #read the n's from the file
    n_list = []
    N = 1
    with open(nFile, 'r') as file:
        for line in file:
            n_list.append(int(line))
            N *= int(line)
    
    #open the encrypted files and read them into hex strings
    enc_list = [enc1, enc2, enc3]
    for i in range(3):
        enc_list[i] = BitVector(hexstring = open(enc_list[i], 'r').read())
    
    #iterate through the file and decrypt each block
    #I used a counter to iterate through the file and decrypt each block again
    #instead of using more_to_read because it seems that more_to_read is not working when reading from a hex file
    a = 0
    while(enc_list[0].length() >= a + 256):
        #decrypt the block
        #get the next 256 bits from each file
        bv1 = enc_list[0][a:a+256]
        bv2 = enc_list[1][a:a+256]
        bv3 = enc_list[2][a:a+256]
        #increment a by 256
        a += 256
        #decrypt the block
        x = crt(bv1.int_val(), bv2.int_val(), bv3.int_val(), N, n_list)
        #take the cube root of the decrypted block
        pRt = solve_pRoot(3, x)
        #write the decrypted block to the file
        bv_pRt = BitVector(intVal=pRt, size=256)
        #remove the padding and write the block to the file
        bv_pRt = bv_pRt[128:]
        cracked_file.write(bv_pRt.get_bitvector_in_ascii())

if __name__ == '__main__':
    if sys.argv[1] == '-e':
        message = sys.argv[2]
        enc1 = sys.argv[3]
        enc2 = sys.argv[4]
        enc3 = sys.argv[5]
        nFile = sys.argv[6]
        encrypt(message, enc1, enc2, enc3, nFile)
    
    elif sys.argv[1] == '-c':
        enc1 = sys.argv[2]
        enc2 = sys.argv[3]
        enc3 = sys.argv[4]
        nFile = sys.argv[5]
        cracked = sys.argv[6]
        crack(enc1, enc2, enc3, nFile, cracked)

    else:
        print("Error invalid format.")