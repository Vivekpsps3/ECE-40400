# Homework Number: HW06
# Name: Raghava Vivekananda Panchagnula
# ECN Login: rpanchag
# Due Date: 2/27/2024

import sys
from BitVector import *
from PrimeGenerator import *

p_file = "p.txt"
q_file = "q.txt"

class RSA():
    def __init__(self,e) -> None:
        self.e = e
        try:
            with open("p.txt", "r") as f:
                self.p = int(f.read())
            with open("q.txt", "r") as f:
                self.q = int(f.read())
        except:
            print("p.txt and/or q.txt not found. Set to 3,5 for the time being.")
            self.p = 3
            self.q = 5
        self.n = self.p * self.q

        #d is the modular multiplicative inverse of e mod (p-1)(q-1)
        n = (self.p - 1) * (self.q - 1)
        e_m_inv = BitVector(intVal=self.e).multiplicative_inverse(BitVector(intVal = n))
        self.d = e_m_inv.int_val() % n
    
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        #read the input file
        bv = BitVector(filename=plaintext)
        output_file = open(ciphertext, 'w')

        while bv.more_to_read:
            #read 128 bits from the file and pad from right if necessary
            bitvec = bv.read_bits_from_file(128)
            bitvec.pad_from_right(128 - bitvec.length())
            #pad from left to make it 256 bits
            bitvec.pad_from_left(128)

            #int_val will be the encrypted block and then write it to file
            int_val = pow(int(bitvec), self.e, self.n)
            bitvec = BitVector(intVal= int_val, size=256)
            output_file.write(bitvec.get_bitvector_in_hex())

        output_file.close()
    
    def decrypt(self, ciphertext:str, recovered_plaintext:str) -> None:
        cipher_file = open(ciphertext, 'r')
        input_data = cipher_file.read()

        bv = BitVector(hexstring=input_data)
        output_file = open(recovered_plaintext, 'w')

        i = 0

        while(i < bv.length()):
            bitvec = bv[i:i+256].int_val()
            decrypted_int = self.exec_crt(bitvec)
            decrypted_bv = BitVector(intVal=decrypted_int, size=256)

            decrypted_text_bv = decrypted_bv[128:]
            output_file.write(decrypted_text_bv.get_bitvector_in_ascii())
            i += 256

        output_file.close()

        return

    def generate_keys(self, p_file, q_file) -> None:
        pFILE = open(p_file, 'w')
        qFILE = open(q_file, 'w')

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
        while(p == q or self.find_gcd(p-1, self.e) != 1 or self.find_gcd(q-1, self.e) != 1):
            p = prime_gen.findPrime()
            q = prime_gen.findPrime()
        
        
        #write p and q to file and close
        pFILE.write(str(p))
        qFILE.write(str(q))
        pFILE.close()
        qFILE.close()

    def exec_crt(self, bv_int) -> int:
        vP = pow(bv_int, self.d, self.p)
        vQ = pow(bv_int, self.d, self.q)
        qI = BitVector(intVal=self.q).multiplicative_inverse(BitVector(intVal=self.p))
        xP = self.q * qI.int_val()
        pI = BitVector(intVal=self.p).multiplicative_inverse(BitVector(intVal=self.q))
        xQ = self.p * pI.int_val()
        pt = (vP * xP + vQ * xQ) % (self.p * self.q)
        return pt

    def find_gcd(self, a, b) -> int:
        while(b):
            a, b = b, a % b
        return abs(a)

if __name__ == "__main__":
    cipher = RSA(e=65537)
    flag = sys.argv[1]
    if flag == '-g':
        p_file = sys.argv[2]
        q_file = sys.argv[3]
        cipher.generate_keys(p_file, q_file)
    else:
        inputfile = sys.argv[2]
        p_file = sys.argv[3]
        q_file = sys.argv[4]
        outputfile = sys.argv[5]
        
        if flag == '-e':
            cipher.encrypt(inputfile, outputfile)
        elif flag == '-d':
            cipher.decrypt(inputfile, outputfile)
        else:
            print("Invalid flag")
            sys.exit(1)