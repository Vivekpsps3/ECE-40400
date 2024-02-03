#!/usr/bin/env perl

## gen_tables.pl
## Avi Kak (February 16, 2015)

##  This is a Perl implementation of the byte substitution explanations in Sections
##  8.5 and 8.5.1 of Lecture 8.  In keeping with the explanation in Section 8.5, the
##  goal here is to construct two 256-element arrays for byte substitution, one for
##  the SubBytes step that goes into the encryption rounds of the AES algorithm, and
##  the other for the InvSubBytes step that goes into the decryption rounds. 

use strict;
use warnings;
use Algorithm::BitVector;

my $AES_modulus = Algorithm::BitVector->new(bitstring => '100011011');

my @subBytesTable;                                   # SBox for encryption
my @invSubBytesTable;                                # SBox for decryption

sub genTables {
    my $c = Algorithm::BitVector->new(bitstring => '01100011');
    my $d = Algorithm::BitVector->new(bitstring => '00000101');
    foreach my $i (0..255) {
        # For the encryption SBox:
        my $a = $i == 0 ? Algorithm::BitVector->new(intVal => 0) :
            Algorithm::BitVector->new(intVal => $i, size => 8)->gf_MI($AES_modulus, 8);
        # For bit scrambling for the encryption SBox entries:
        my ($a1,$a2,$a3,$a4) = map $a->deep_copy(), 0 .. 3;
        $a ^= ($a1 >> 4) ^ ($a2 >> 5) ^ ($a3 >> 6) ^ ($a4 >> 7) ^ $c;
        push @subBytesTable, int($a);
        # For the decryption Sbox:
        my $b = Algorithm::BitVector->new(intVal => $i, size => 8);
        # For bit scrambling for the decryption SBox entries:
        my ($b1,$b2,$b3) = map $b->deep_copy(), 0 .. 2;
        $b = ($b1 >> 2) ^ ($b2 >> 5) ^ ($b3 >> 7) ^ $d;
        my $check = $b->gf_MI($AES_modulus, 8);
        $b = ref($check) eq 'Algorithm::BitVector' ? $check : 0; 
        push @invSubBytesTable, int($b);
    }
}

genTables();
print "SBox for Encryption:\n";
print "@subBytesTable\n";
print "\nSBox for Decryption:\n";
print "@invSubBytesTable\n";
