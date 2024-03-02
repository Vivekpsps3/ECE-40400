from cryptBreak import cryptbreak
from BitVector import *

randomInteger = 1616
key_bv = BitVector(intVal = randomInteger, size = 16)
outputtext = cryptbreak('cipherText.txt', key_bv)
if "Ferrari" in outputtext:
    print("Encryption Broken")
    print(outputtext)
    print(randomInteger)
    print(key_bv)
else:
    print("Encryption Not Broken")