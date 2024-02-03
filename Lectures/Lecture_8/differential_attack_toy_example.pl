#!/usr/bin/perl -w

##  differential_attack_toy_example.pl

##  Avi Kak  (March 4, 2015)

##  This script is a toy example to illustrate some of the key elements of a
##  differential attack on a block cipher. 

##  We assume that our block size is one byte and the SBox consists of finding a
##  substitute byte by table lookup. We further assume that each round consists of
##  one byte substitution step followed by xor'ing the substituted byte with the
##  round key.  The round key is the encryption key that is circularly shifted to the
##  right by one position for each round.

##  Since you are likely to run this script repeatedly as you experiment with
##  different strategies for estimating the subkey used in the last round, the script
##  makes it easy to do so by writing the information that is likely to stay constant
##  from one run to the next to disk-based DBM files.  The script creates the
##  following DBM files:
##
##     worst_differentials.dir  and  worst_differentials.pag   --     See Line (A14)
##
##  These DBM files are created the very first time you run this script.  Your
##  subsequent runs of this script will be much faster since this DBM database
##  would not need to be created again.  Should there be a need to run the script
##  starting from ground zero, you can clear the DBM files created in your directory
##  by calling the script:
##
##       clean_db_files.pl
##
##  Finally, if you set the number of tries in Line (A10) to a large number and you
##  are tired of waiting, you can kill the script at any time you wish.  To see the
##  vote counts accumulated up to that point for the different possible candidates
##  for the last round key, just run the script:
##
##       get_vote_counts.pl
##
##  The scripts clean_db_files.pl and get_vote_counts.pl are in the gzipped archive
##  that goes with Lecture 8 at the lecture notes web site.

use strict;
use Algorithm::BitVector;
$|++;

my $debug = 1;
my $AES_modulus = Algorithm::BitVector->new(bitstring => '100011011');                   #(A1)
my $number_of_rounds = 2;                                                                #(A2)
my $encryption_key = Algorithm::BitVector->new(bitstring => '10001011');                 #(A3)
my $differential_hist;                                                                   #(A4)
my %decryption_inverses;                                                                 #(A5)
my %worst_differentials;                                                                 #(A6)
my @worst_input_differentials;                                                           #(A7)
my @worst_output_differentials;                                                          #(A8)

my $hist_threshold = 8;                                                                  #(A9)
my $tries = 500;                                                                         #(A10)

unlink glob "votes.*";                                                                   #(A11)
dbmopen my %votes_for_keys, "votes", 0644                                   
    or die "cannot create DBM file: $!";                                                 #(A12)

#  This lookup table is used for the byte substituion step during encryption in the
#  subroutine defined in lines (C1) through (C14).  By experimenting with the script
#  differentials_frequency_calculator.pl this lookup table was found to yield a good
#  non-uniform histogram for the plaintext/ciphertext differentials.
my @lookuptable = qw(213 170 104 116 66 14 76 219 200 42 22 17 241 197 41 216 85 140 
                     183 244 235 6 118 208 74 218 99 44 1 89 11 205 195 125 47 236 113 
                     237 131 109 102 9 21 220 59 154 119 148 38 120 13 217 16 100 191 81 
                     240 196 122 83 177 229 142 35 88 48 167 0 29 153 163 146 166 77 79 
                     43 10 194 232 189 238 164 204 111 69 51 126 62 211 242 70 214 247 55 
                     202 78 239 114 184 112 228 84 152 187 45 49 175 58 253 72 95 19 37 
                     73 145 87 198 71 159 34 91 168 250 255 8 121 96 50 141 181 67 26 243 
                     130 68 61 24 105 210 172 139 136 128 157 133 80 93 39 2 143 161 186 33 
                     144 178 30 92 138 169 86 249 252 155 193 63 223 203 245 129 4 171 
                     115 3 40 151 7 188 231 174 25 23 207 180 56 46 206 215 227 162 199 
                     97 147 182 149 108 36 132 5 12 103 110 209 160 137 53 224 185 173 
                     20 222 246 28 179 134 75 254 57 60 234 52 165 225 248 31 230 156 
                     124 233 158 27 18 94 65 32 54 106 192 221 190 101 98 251 212 150 
                     201 117 127 107 176 226 135 123 82 15 64 90);                       #(A13)

#  In what follows, we first check if the worst_differentials DBM files were created
#  previously by this script.  If they are already on the disk, create the disk-based
#  hash %worst_differentials_db from the data in those files.  If not, create the DBM
#  files so that they can subsequently be populated by the call in line (A18).
#  [IMPORTANT: In a more realistic attack logic, you will need to create a more
#  general version of the code in lines (A14) through (A21) so that you find the
#  histogram for the plaintext/ciphertext differentials not for just one round, but
#  for all the rounds involved. See the tutorial by Howard Heys for this important
#  point.]
dbmopen my %worst_differentials_db, "worst_differentials", 0644 
              or die "Can't open DBM file: $!";                                          #(A14)
unless (keys %worst_differentials_db) {                                                  #(A15)
    foreach my $i (0..255) {                                                             #(A16)
        foreach my $j (0..255) {                                                         #(A17)
           $differential_hist->[$i][$j] = 0;                                             #(A18)
        }
    }
    gen_differential_histogram();                                                        #(A19)
    #  The call shown below will show that part of the histogram for which both 
    #  the input and the output differentials are in the range (32, 63). 
    display_portion_of_histogram(32, 64) if $debug;                                      #(A20)
    #  From the 2D input/output histogram for the differentials, now represent that
    #  information has a hash in which the keys are the plaintext differentials and
    #  the value associated with each key the ciphertext differential whose histogram
    #  count exceeds the supplied threshold:
    find_most_probable_differentials($hist_threshold);                                   #(A21)
}
%worst_differentials = %worst_differentials_db;                                          #(A22)
die"no candidates for differentials: $!" if keys %worst_differentials == 0;              #(A23)
@worst_input_differentials = sort {$a <=> $b} keys %worst_differentials;                 #(A24)
@worst_output_differentials =  @worst_differentials{@worst_input_differentials};         #(A25)
if ($debug) {
    print "\nworst input differentials: @worst_input_differentials\n";                   #(A26)
    print "\nworst output differentials: @worst_output_differentials\n";                 #(A27)
}

#  The following call makes a hash that does the opposite of what is achieved by
#  indexing into the lookup table of line (A13). It fills the hash
#  '%decryption_inverses' with <key,value> pairs, with the keys being the ciphertext
#  bytes and the values being the corresponding plaintext bytes.
find_inverses_for_decryption();                                                          #(A28)

estimate_last_round_key();                                                               #(A29)

#  Now print out the ten most voted for keys.  To see the votes for all possible keys,
#  execute the script get_vote_counts.pl separately after running this script.
print "no votes for any candidates for the last round key\n" 
                                    if keys %votes_for_keys == 0;                        #(A30)
if (scalar keys %votes_for_keys) {                                                       #(A31)
    my @vote_sorted_keys = 
            sort {$votes_for_keys{$b} <=> $votes_for_keys{$a}} keys %votes_for_keys;     #(A32)
    print "\nDisplaying the keys with the largest number of votes: @vote_sorted_keys[0..9]\n";
                                                                                         #(A33)
}

###################################  Subroutines   ###########################################

#  The differential attack:
sub estimate_last_round_key {                                                            #(B1)
    my $attempted = 0;                                                                   #(B2)
    foreach my $i (2..255) {                                                             #(B3)
        print "+ " if $debug;                                                            #(B4)
        my $plaintext1 = Algorithm::BitVector->new(intVal => $i, size => 8);             #(B5)
        foreach my $j (2..255) {                                                         #(B6)
            my $plaintext2 = Algorithm::BitVector->new(intVal => $j, size => 8);         #(B7)
            my $input_differential = $plaintext1 ^ $plaintext2;                          #(B8)
            next if int($input_differential) < 2;                                        #(B9)
            next unless exists $worst_differentials{int($input_differential)};           #(B10)
            print "- " if $debug;                                                        #(B11)
            my ($ciphertext1, $ciphertext2) =                                            #(B12)
              (encrypt($plaintext1, $encryption_key), encrypt($plaintext2, $encryption_key));
            my $output_differential = $ciphertext1 ^ $ciphertext2;                       #(B13)
            next if int($output_differential) < 2;                                       #(B14)
            last if $attempted++ > $tries;                                               #(B15)
            print " attempts made $attempted " if $attempted % 500 == 0;                 #(B16)
            print "| " if $debug;                                                        #(B17)
            foreach my $key (0..255) {                                                   #(B18)
                print ". " if $debug;                                                    #(B19)
                my $key_bv = Algorithm::BitVector->new(intVal => $key, size => 8);       #(B20)
                my $partial_decrypt_int1 = $decryption_inverses{int($ciphertext1 ^ $key_bv )};
                                                                                         #(B21)
                my $partial_decrypt_int2 = $decryption_inverses{int($ciphertext2 ^ $key_bv )};
                                                                                         #(B22)
                my $delta = $partial_decrypt_int1 ^ $partial_decrypt_int2;               #(B23)
                if (exists $worst_differentials{$delta}) {                               #(B24)
                    print "  voted  " if $debug;                                         #(B25)
                    $votes_for_keys{$key}++;                                             #(B26)
                }
            }
        }
    }
}

sub encrypt {                                                                            #(C1)
    my $plaintext = shift;              # must be a bitvector                            #(C2)
    my $key = shift;                    # must be a bitvector                            #(C3)
    my $round_input = $plaintext;                                                        #(C4)
    my $round_output;                                                                    #(C5)
    my $round_key = $key;                                                                #(C6)
    if ($number_of_rounds > 1) {                                                         #(C7)
        foreach my $round (0..$number_of_rounds-1) {                                     #(C8)
            $round_output = get_sbox_output_lookup($round_input) ^ $round_key;           #(C9)
            $round_input = $round_output;                                                #(C10)
            $round_key = $round_key >> 1;                                                #(C11)
        }
    } else {                                                                             #(C12)
        $round_output = get_sbox_output_lookup($round_input) ^ $key;                     #(C13)
    }
    return $round_output;                                                                #(C14)
}

#  Since the SubBytes step in encryption involves taking the square of a byte in
#  GF(2^8) based on AES modulus, for invSubBytes step for decryption will involve
#  taking square-roots of the bytes in GF(2^8).  This subroutine calculates these
#  square-roots.
sub find_inverses_for_decryption {                                                       #(D1)
    foreach my $i (0 .. @lookuptable - 1) {
        $decryption_inverses{$lookuptable[$i]} = $i;
    }
}

#  This function represents the histogram of the plaintext/ciphertext differentials
#  in the form of a hash in which the keys are the plaintext differentials and the
#  value for each plaintext differential the ciphertext differential where the
#  histogram count exceeds the threshold.
sub find_most_probable_differentials {                                                   #(F1)
    my $threshold = shift;                                                               #(F2)
    foreach my $i (0..255) {                                                             #(F3)
        foreach my $j (0..255) {                                                         #(F4)
           $worst_differentials_db{$i} = $j if $differential_hist->[$i][$j] > $threshold;#(F5)
        }
    }
}

#  This subroutine generates a 2D histogram in which one axis stands for the
#  plaintext differentials and the other axis the ciphertext differentials.  The
#  count in each bin is the number of times that particular relationship is seen
#  between the plaintext differentials and the ciphertext differentials.
sub gen_differential_histogram {                                                         #(G1)
    foreach my $i (0 .. 255) {                                                           #(G2)
        print "\ngen_differential_hist: i=$i\n" if $debug;                               #(G3)
        foreach my $j (0 .. 255) {                                                       #(G4)
            print ". " if $debug;                                                        #(G5)
            my ($a, $b) = (Algorithm::BitVector->new(intVal => $i, size => 8), 
                           Algorithm::BitVector->new(intVal => $j, size => 8));          #(G6)
            my $input_differential = int($a ^ $b);                                       #(G7)
            my ($c, $d) = (get_sbox_output_lookup($a), get_sbox_output_lookup($b));      #(B9)
            my $output_differential = int($c ^ $d);                                      #(G9)
            $differential_hist->[$input_differential][$output_differential]++;           #(G10)
        }
    }
}

sub get_sbox_output_lookup {                                                             #(D1)
    my $in = shift;                                                                      #(D2)
    return Algorithm::BitVector->new(intVal => $lookuptable[int($in)], size => 8);       #(D3)
}

#  Displays in your terminal window the bin counts in the two-dimensional histogram
#  for the input/output mapping of the differentials.  You can control the portion of
#  the 2D histogram that is output by using the first argument to set the lower bin
#  index and the second argument the upper bin index along both dimensions.
#  Therefore, what you see is always a square portion of the overall histogram.
sub display_portion_of_histogram {                                                       #(J1)
    my $lower = shift;                                                                   #(J2)
    my $upper = shift;                                                                   #(J3)
    foreach my $i ($lower .. $upper - 1) {                                               #(J4)
        print "\n";                                                                      #(J5)
        foreach my $j ($lower .. $upper - 1) {                                           #(J6)
            print "$differential_hist->[$i][$j] ";                                       #(J7)
        }
    }
}

