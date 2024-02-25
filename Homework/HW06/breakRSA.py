# Homework Number: HW06
# Name: Raghava Vivekananda Panchagnula
# ECN Login: rpanchag
# Due Date: 2/27/2024

import sys
from BitVector import *
from solve_pRoot import *
from PrimeGenerator import *

e = 3

def encrypt(message, enc1, enc2, enc3, nFile):
    
    pass

def crack(enc1, enc2, enc3, nFile, cracked):
    pass

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
        print("Error invalid format given!")