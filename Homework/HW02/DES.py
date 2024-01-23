import sys
import BitVector


expansion_permutation = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                      9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                     62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                     13,5,60,52,44,36,28,20,12,4,27,19,11,3]

key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                      3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                     54,29,39,50,44,32,47,43,48,38,55,33,52,
                     45,41,49,35,28,31]

shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

class DES():
    def __init__(self, key):
        pass
        

    def encrypt(self, message_file, outfile):
        key = get_encryption_key()
        round_key = extract_round_key( key )
        bv = BitVector( 'filename.txt' )
        while (bv.more_to_read):
            bitvec = bv.read_bits_from_file( 64 )
            if bitvec.getsize() > 0:
                [LE, RE] = bitvec.divide_into_two()
                newRE = RE.permute( expansion_permutation )
                out_xor = newRE.bv_xor( round_key )

                '''
                now comes the hard part --- the substition boxes

                Let's say after the substitution boxes and another
                permutation (P in Section 3.3.4), the output for RE is
                RE_modified.

                When you join the two halves of the bit string
                again, the rule to follow (from Fig. 4 in page 21) is
                either

                final_string = RE followed by (RE_modified xored with LE)

                or

                final_string = LE followed by (LE_modified xored with RE)

                depending upon whether you prefer to do the substitutions
                in the right half (as shown in Fig. 4) or in the left
                half.

                The important thing to note is that the swap between the
                two halves shown in Fig. 4 is essential to the working
                of the algorithm even in a single-round implementation
                of the cipher, especially if you want to use the same
                algorithm for both encryption and decryption (see Fig.
                3 page 15). The two rules shown above include this swap.
                '''
    def decrypt(self, encrypted_file, outfile):
        pass

def get_encryption_key():
    key = ""
    while True:
        if sys.version_info[0] == 3:
            key = input("\nEnter a string of 8 characters for the key: ")
        else:
            key = raw_input("\nEnter a string of 8 characters for the key: ")
        if len(key) != 8:
            print("\nKey generation needs 8 characters exactly.  Try again.\n")
            continue
        else:
            break
    key = BitVector(textstring = key)
    key = key.permute(key_permutation_1)
    return key

def generate_round_keys(encryption_key):
    round_keys = []
    key = encryption_key.deep_copy()
    for round_count in range(16):
        [LKey, RKey] = key.divide_into_two()    
        shift = shifts_for_round_key_gen[round_count]
        LKey << shift
        RKey << shift
        key = LKey + RKey
        round_key = key.permute(key_permutation_2)
        round_keys.append(round_key)
    return round_keys
if __name__ == "__main__":
    cipher = DES(key = sys.argv[3])
