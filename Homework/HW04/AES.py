import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []                                                  # for encryption
invSubBytesTable = []   

class AES():
    def __init__(self, keyfile:str) -> None:
        # Read the key from the file
        with open(keyfile, 'r') as file:
            key = file.read()
        key_bv = BitVector(textstring = key)
        self.key_words = gen_key_schedule_256(key_bv)
        self.round_keys = gen_round_keys(self.key_words)
        pass

    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        bv = BitVector(filename = plaintext)
        FILEOUT = open(ciphertext, 'w')
        output = BitVector(size = 0)
        round_keys = self.round_keys

        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(128)
            if bitvec.length() > 0:
                bitvec.pad_from_right(128 - bitvec.length())
            
            bitvec = bitvec ^ round_keys[0]
            state_array = gen_state_array(bitvec)
 
            for i in range(1,14):
                state_array = sub_bytes(state_array)
                state_array = shift_rows(state_array)
                state_array = mix_columns(state_array)
                state_array = add_round_key(state_array, round_keys[i])
                state_array = gen_state_array(state_array)
            state_array = sub_bytes(state_array)
            state_array = shift_rows(state_array)
            state_array = add_round_key(state_array, round_keys[14])
            output += state_array
        
        output = output.get_bitvector_in_hex()
        FILEOUT.write(output)
        FILEOUT.close()
        
    def decrypt(self, ciphertext:str, decrypted:str) -> None:
        FILEIN = open(ciphertext, 'r')
        ciphertext = FILEIN.read()
        FILEIN.close()
        bv = BitVector(hexstring = ciphertext)

        # bv = BitVector(filename = ciphertext)
        FILEOUT = open(decrypted, 'wb')
        output = BitVector(size = 0)
        round_keys = self.round_keys
        round_keys = round_keys[::-1]

        rem = bv.length() % 128
        counter = 0
        if (rem == 0):
            quotient = bv.length() // 128
            quotient = quotient + 1
            quotient = quotient * 128
            bv.pad_from_right(quotient - bv.length())

        #while(bv.more_to_read):
        while (bv.length() > counter + 128):
            bitvec = bv[counter:counter+128]
            # bitvec = bv.read_bits_from_file(128)
            # if bitvec.length() < 128:
            #     bitvec.pad_from_right(128 - bitvec.length())
            
            bitvec = bitvec ^ round_keys[0]
            state_array = gen_state_array(bitvec)
 
            for i in range(1,14):
                state_array = inv_shift_rows(state_array)
                state_array = inv_sub_bytes(state_array)
                state_array = add_round_key(state_array, round_keys[i])
                state_array = gen_state_array(state_array)
                state_array = inv_mix_columns(state_array)

            state_array = inv_shift_rows(state_array)
            state_array = inv_sub_bytes(state_array)
            state_array = add_round_key(state_array, round_keys[14])
            output += state_array
            counter += 128
        
        output.write_to_file(FILEOUT)
        FILEOUT.close()


def gen_round_keys(key_words):
    key_schedule = []
    #print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        if word_index % 4 == 0: continue
        key_schedule.append(keyword_in_ints)
    #num_rounds is always 14 for 256-bit AES
    num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])
    return round_keys

def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

def gen_key_schedule_256(key_bv):
    genTables()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, subBytesTable)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 subBytesTable[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_state_array(bitvec):
    state_array = [[0 for i in range(4)] for j in range(4)]
    for i in range(4):
        for j in range(4):
            state_array[j][i] = bitvec[32*i+8*j:32*i+8*j+8].int_val()

    return state_array

def sub_bytes(state_array):
    for i in range(4):
        for j in range(4):
            state_array[i][j] = subBytesTable[state_array[i][j]]
    return state_array

def inv_sub_bytes(state_array):
    for i in range(4):
        for j in range(4):
            state_array[i][j] = invSubBytesTable[state_array[i][j]]
    return state_array

def shift_rows(state_array):
    state_array[1] = state_array[1][1:] + state_array[1][:1]
    state_array[2] = state_array[2][2:] + state_array[2][:2]
    state_array[3] = state_array[3][3:] + state_array[3][:3]
    return state_array

def inv_shift_rows(state_array):
    state_array[1] = state_array[1][3:] + state_array[1][:3]
    state_array[2] = state_array[2][2:] + state_array[2][:2]
    state_array[3] = state_array[3][1:] + state_array[3][:1]
    return state_array

def mix_columns(state_array):
    for i in range(4):
        for j in range(4):
            state_array[i][j] = BitVector(intVal = state_array[i][j], size=8)
    
    mix_col = [[BitVector(size=8) for i in range(4)] for j in range(4)]

    for i in range(4):
        for j in range(4):
            mix_col[i][j] = state_array[i][j].deep_copy()

    for i in range(4):
        state_array[0][i] = mix_col[0][i].gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8) ^ mix_col[1][i].gf_multiply_modular(BitVector(intVal = 0x03), AES_modulus, 8) ^ mix_col[2][i] ^ mix_col[3][i]
        state_array[1][i] = mix_col[0][i] ^ mix_col[1][i].gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8) ^ mix_col[2][i].gf_multiply_modular(BitVector(intVal = 0x03), AES_modulus, 8) ^ mix_col[3][i]
        state_array[2][i] = mix_col[0][i] ^ mix_col[1][i] ^ mix_col[2][i].gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8) ^ mix_col[3][i].gf_multiply_modular(BitVector(intVal = 0x03), AES_modulus, 8)
        state_array[3][i] = mix_col[0][i].gf_multiply_modular(BitVector(intVal = 0x03), AES_modulus, 8) ^ mix_col[1][i] ^ mix_col[2][i] ^ mix_col[3][i].gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    
    for i in range(4):
        for j in range(4):
            state_array[i][j] = state_array[i][j].int_val()
    
    return state_array

def inv_mix_columns(state_array):
    for i in range(4):
        for j in range(4):
            state_array[i][j] = BitVector(intVal = state_array[i][j], size=8)
    
    mix_col = [[BitVector(size=8) for i in range(4)] for j in range(4)]

    for i in range(4):
        for j in range(4):
            mix_col[i][j] = state_array[i][j].deep_copy()

    for i in range(4):
        state_array[0][i] = mix_col[0][i].gf_multiply_modular(BitVector(intVal = 0x0e), AES_modulus, 8) ^ mix_col[1][i].gf_multiply_modular(BitVector(intVal = 0x0b), AES_modulus, 8) ^ mix_col[2][i].gf_multiply_modular(BitVector(intVal = 0x0d), AES_modulus, 8) ^ mix_col[3][i].gf_multiply_modular(BitVector(intVal = 0x09), AES_modulus, 8)
        state_array[1][i] = mix_col[0][i].gf_multiply_modular(BitVector(intVal = 0x09), AES_modulus, 8) ^ mix_col[1][i].gf_multiply_modular(BitVector(intVal = 0x0e), AES_modulus, 8) ^ mix_col[2][i].gf_multiply_modular(BitVector(intVal = 0x0b), AES_modulus, 8) ^ mix_col[3][i].gf_multiply_modular(BitVector(intVal = 0x0d), AES_modulus, 8)
        state_array[2][i] = mix_col[0][i].gf_multiply_modular(BitVector(intVal = 0x0d), AES_modulus, 8) ^ mix_col[1][i].gf_multiply_modular(BitVector(intVal = 0x09), AES_modulus, 8) ^ mix_col[2][i].gf_multiply_modular(BitVector(intVal = 0x0e), AES_modulus, 8) ^ mix_col[3][i].gf_multiply_modular(BitVector(intVal = 0x0b), AES_modulus, 8)
        state_array[3][i] = mix_col[0][i].gf_multiply_modular(BitVector(intVal = 0x0b), AES_modulus, 8) ^ mix_col[1][i].gf_multiply_modular(BitVector(intVal = 0x0d), AES_modulus, 8) ^ mix_col[2][i].gf_multiply_modular(BitVector(intVal = 0x09), AES_modulus, 8) ^ mix_col[3][i].gf_multiply_modular(BitVector(intVal = 0x0e), AES_modulus, 8)
    
    for i in range(4):
        for j in range(4):
            state_array[i][j] = state_array[i][j].int_val()
    
    return state_array

def get_bv_from_state_array(state_array):
    bv = BitVector(size=0)
    for i in range(4):
        for j in range(4):
            val = BitVector(intVal = state_array[j][i], size=8)
            if len(val) < 8:
                val.pad_from_left(8-len(val))
            bv += val
    return bv

def add_round_key(state_array, round_key):
    state_array = get_bv_from_state_array(state_array)
    state_array ^= round_key
    return state_array

if __name__ == "__main__":
    # Check for correct number of CLI arguments
    if len(sys.argv) != 5:
        sys.exit("Incorrect number of CLI arguments. Please use -e or -d as the first argument, the input file as the second argument, the key file as the third argument, and the output file as the fourth argument.")
    
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
        sys.exit("Incorrect CLI argument. Please use -e or -d.")
