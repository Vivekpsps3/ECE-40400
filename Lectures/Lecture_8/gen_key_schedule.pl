#!/usr/bin/perl -w  

##  gen_key_schedule.pl
##  Avi Kak  (February 2, 2018)

##  This script is for demonstrating the AES algorithm for generating the
##  key schedule.

##  It will prompt you for the key size, which must be one of 128, 192, 256.

##  It will also prompt you for a key.  If the key you enter is shorter
##  than what is needed for the AES key size, we add zeros on the right of
##  the key so that its length is as needed by the AES key size.

use strict;
use warnings;
use Algorithm::BitVector 1.26;

my $AES_modulus = Algorithm::BitVector->new(bitstring => '100011011');

my @key_words;
my ($keysize, $key_bv) = get_key_from_user();

if ($keysize == 128) {    
    @key_words = gen_key_schedule_128($key_bv);
} elsif ($keysize == 192) {   
    @key_words = gen_key_schedule_192($key_bv);
} elsif ($keysize == 256) {    
    @key_words = gen_key_schedule_256($key_bv);
} else {
    die "wrong keysize --- aborting";
}

my @key_schedule;
print "\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:\n";

foreach my $word_index (0..@key_words-1) {
    my $word = $key_words[$word_index];
    my @keyword_in_ints;
    foreach my $i (0..3) {
        push @keyword_in_ints, int( $word->get_slice([$i*8..($i+1)*8]) )
    }
    if ($word_index % 4 == 0) {
        print "\n";
    }
    print "word $word_index: @keyword_in_ints\n";
    push @key_schedule, "@keyword_in_ints";
}

my $num_rounds;
if ($keysize == 128) { $num_rounds = 10; }
if ($keysize == 192) { $num_rounds = 12; }
if ($keysize == 256) { $num_rounds = 14; }

my @round_keys = (undef) x ($num_rounds+1);

foreach my $i (0..$num_rounds) {
   $round_keys[$i] = ($key_words[$i*4] + $key_words[$i*4+1] + $key_words[$i*4+2] + 
                                                           $key_words[$i*4+3])->get_bitvector_in_hex();
}
print("\n\nRound keys in hex (first key for input block):\n\n");
foreach my $round_key (@round_keys) {
    print "$round_key\n";
}


##  This is the g() function you see in Figure 4 of Lecture 8.
sub gee {
    my ($keyword, $round_constant, $byte_sub_table) = @_;
    my $rotated_word = $keyword->deep_copy();
    $rotated_word = $rotated_word << 8;
    my $newword = Algorithm::BitVector->new(size => 0);
    foreach my $i (0..3) {
        $newword += Algorithm::BitVector->new(intVal => 
                         $byte_sub_table->[int($rotated_word->get_slice([8*$i..8*($i+1)]))], size => 8);
    }
    $newword->set_slice([0..8], $newword->get_slice([0..8]) ^ $round_constant);
    $round_constant = $round_constant->gf_multiply_modular(Algorithm::BitVector->new(intVal => 0x02), 
                                                                                       $AES_modulus, 8);
    return $newword, $round_constant;
}

sub gen_key_schedule_128 {
    my $key_bv = shift;
    my $byte_sub_table = gen_subbytes_table();
    #  We need 44 keywords in the key schedule for 128 bit AES.  Each keyword is 32-bits
    #  wide. The 128-bit AES uses the first four keywords to xor the input block with.
    #  Subsequently, each of the 10 rounds uses 4 keywords from the key schedule. We will
    #  store all 44 keywords in the list key_words in this function.
    my @key_words = (undef) x 44;
    my $round_constant = Algorithm::BitVector->new(intVal => 0x01, size => 8);
    ($key_words[0],$key_words[1],$key_words[2],$key_words[3]) = 
                                                      map $key_bv->get_slice([$_*32..($_+1)*32]), 0..3;
    foreach my $i (4..43) {
        if ($i%4 == 0) {
            my $kwd;
            ($kwd, $round_constant) = gee($key_words[$i-1], $round_constant, $byte_sub_table);
            $key_words[$i] = $key_words[$i-4] ^ $kwd;
        } else {
            $key_words[$i] = $key_words[$i-4] ^ $key_words[$i-1];
        }
    }
    return @key_words;
}

sub gen_key_schedule_192 {
    my $key_bv = shift;
    my $byte_sub_table = gen_subbytes_table();
    #  We need 52 keywords (each keyword consists of 32 bits) in the key schedule for
    #  192 bit AES.  The 192-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 12 rounds uses 4 keywords from the key
    #  schedule. We will store all 52 keywords in the following list:
    my @key_words = (undef) x 52;
    my $round_constant = Algorithm::BitVector->new(intVal => 0x01, size => 8);
    foreach my $i (0..5) {
        $key_words[$i] = $key_bv->get_slice([$i*32 .. ($i+1)*32]);
    }
    foreach my $i (6..51) {
        if ($i%6 == 0) {
            my $kwd;
            ($kwd, $round_constant) = gee($key_words[$i-1], $round_constant, $byte_sub_table);
            $key_words[$i] = $key_words[$i-6] ^ $kwd;
        } else {
            $key_words[$i] = $key_words[$i-6] ^ $key_words[$i-1];
        }
    }
    return @key_words;
}


sub gen_key_schedule_256 {
    my $key_bv = shift;
    my $byte_sub_table = gen_subbytes_table();
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    my @key_words = (undef) x 60;
    my $round_constant = Algorithm::BitVector->new(intVal => 0x01, size => 8);
    foreach my $i (0..7) {
        $key_words[$i] = $key_bv->get_slice([$i*32 .. ($i+1)*32]);
    }
    foreach my $i (8..59) {
        if ($i%8 == 0) {
            my $kwd;
            ($kwd, $round_constant) = gee($key_words[$i-1], $round_constant, $byte_sub_table);
            $key_words[$i] = $key_words[$i-8] ^ $kwd;
        } elsif (($i - int($i/8)*8) < 4) {
            $key_words[$i] = $key_words[$i-8] ^ $key_words[$i-1];
        } elsif (($i - int($i/8)*8) == 4) { 
            $key_words[$i] = Algorithm::BitVector->new( size => 0);
            foreach my $j (0..3) {
                $key_words[$i] += Algorithm::BitVector->new(intVal => 
                 int($byte_sub_table->[int($key_words[$i-1]->get_slice([8*$j..8*($j+1)]))]), size => 8);
            }
            $key_words[$i] = $key_words[$i] ^ $key_words[$i-8]; 
        } elsif ( (($i - int($i/8)*8) > 4) && (($i - int($i/8)*8) < 8) ) {
            $key_words[$i] = $key_words[$i-8] ^ $key_words[$i-1];
        } else {
            die "error in key scheduling algo for i = $i\n";
        }
    }
    return @key_words;
}

sub gen_subbytes_table {
    my @subBytesTable;                                   # SBox for encryption
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
    }
    return \@subBytesTable;
}

sub get_key_from_user {
    my ($key, $keysize);
    print "\nAES key size: ";
    while ( $keysize = <STDIN> ) {
        chomp $keysize;
        if (($keysize != 128) && ($keysize != 192) && ($keysize != 256)) {
            die "\nkeysize is wrong (must be one of 128, 192, or 256) --- aborting";
        }
        last;
    }
    print "\nEnter key (any number of chars): "; 
    while ( $key = <STDIN> ) {
        chomp $key;
        last;
    }    
    if (length $key < int($keysize/8)) {
        $key .= '0' x ($keysize/8 - length $key);
    }
    my $key_bv = Algorithm::BitVector->new( textstring => $key );
    return $keysize, $key_bv;
}

