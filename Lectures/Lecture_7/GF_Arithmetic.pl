#!/usr/bin/env perl

##   GF_Arithmetic.pl
##   Author: Avi Kak
##   Date:   February 5, 2016

##   Note: The code you see in this file has already been incorporated in
##         Version 1.24 and above of the Perl Algorithm::BitVector module.  
##         If you like object-oriented approach to scripting, just use that 
##         module directly.  The documentation in that module shows how to
##         make function calls for doing GF(2^n) arithmetic.

use strict;
use warnings;
use Algorithm::BitVector;

my $mod = Algorithm::BitVector->new( bitstring => '100011011' );               # AES modulus

my $a = Algorithm::BitVector->new( bitstring => '10000000' );
my $result = gf_MI( $a, $mod, 8 );
print "\n\nMI of  $a is: $result\n";

$a = Algorithm::BitVector->new( bitstring => '10010101' );
$result = gf_MI( $a, $mod, 8 );
print "\nMI of $a is: $result\n";

$a = Algorithm::BitVector->new( bitstring => '00000000' );
$result = gf_MI( $a, $mod, 8 );
print "\nMI of $a is: $result\n";



##  Using the arithmetic of the Galois Field GF(2^n), this function divides 
##  the bit pattern $num by the modulus bit pattern $mod
sub gf_divide {
    my ($num, $mod, $n) = @_;
    die "Modulus bit pattern too long" if $mod->length() > $n + 1;
    my $quotient = Algorithm::BitVector->new( intVal => 0, size => $num->length() );
    my $remainder = $num->deep_copy();
    for (my $i = 0; $i < $num->length(); $i++) {
        my $mod_highest_power = $mod->length() - $mod->next_set_bit(0) - 1;        
        my $remainder_highest_power;
        if ($remainder->next_set_bit(0) == -1) {    
            $remainder_highest_power = 0;
        } else {
            $remainder_highest_power = $remainder->length() - $remainder->next_set_bit(0) - 1;
        }
        if (($remainder_highest_power < $mod_highest_power) or (int($remainder)==0)) {
            last;
        } else {
            my $exponent_shift = $remainder_highest_power - $mod_highest_power;
            $quotient->set_bit($quotient->length() - $exponent_shift - 1, 1);
            my $quotient_mod_product = $mod->deep_copy();
            $quotient_mod_product->pad_from_left($remainder->length() - $mod->length() );
            $quotient_mod_product->shift_left($exponent_shift);
            $remainder ^= $quotient_mod_product;
        }
    }
    $remainder = Algorithm::BitVector->new(bitlist => 
                     $remainder->get_bit([$remainder->length()-$n .. $remainder->length()-1])) 
                     if $remainder->length() > $n;
    return ($quotient, $remainder);
}

##  Using the arithmetic of the Galois Field GF(2^n), this function multiplies
##  the bit pattern $arg1 by the bit pattern $arg2
sub gf_multiply {
    my ($arg1,$arg2) = @_;
    my ($a, $b) = ($arg1->deep_copy(), $arg2->deep_copy());
    my $a_highest_power = $a->length() - $a->next_set_bit(0) - 1;
    my $b_highest_power = $b->length() - $b->next_set_bit(0) - 1;
    my $result = Algorithm::BitVector->new( size => $a->length( )+ $b->length() );
    $a->pad_from_left( $result->length() - $a->length() );
    $b->pad_from_left( $result->length() - $b->length() );
    foreach my $i (0 .. $b->length() - 1) {
        my $bit = $b->get_bit($i);
        if ($bit == 1) {
            my $power = $b->length() - $i - 1;
            my $a_copy = $a->deep_copy();
            $a_copy->shift_left( $power );
            $result ^= $a_copy;
        }
    }
    return $result;
}

##  Using the arithmetic of the Galois Field GF(2^n), this function returns $a
##  divided by $b modulo the bit pattern in $mod
sub gf_multiply_modular {
    my ($a, $b, $mod, $n) = @_;
    my $a_copy = $a->deep_copy();
    my $b_copy = $b->deep_copy();
    my $product = gf_multiply($a_copy,$b_copy);
    my ($quotient, $remainder) = gf_divide($product, $mod, $n);
    return $remainder;
}

##  Using the arithmetic of the Galois Field GF(2^n), this function returns the
##  multiplicative inverse of the bit pattern $num when the modulus polynomial
##  is represented by the bit pattern $mod
sub gf_MI {
    my ($num, $mod, $n) = @_;
    my $NUM = $num->deep_copy(); my $MOD = $mod->deep_copy();
    my $x = Algorithm::BitVector->new( size => $mod->length() );
    my $x_old = Algorithm::BitVector->new( intVal => 1, size => $mod->length() );
    my $y = Algorithm::BitVector->new( intVal => 1, size => $mod->length() );
    my $y_old = Algorithm::BitVector->new( size => $mod->length() );
    my ($quotient, $remainder);
    while (int($mod)) {
        ($quotient, $remainder) = gf_divide($num, $mod, $n);
        ($num, $mod) = ($mod, $remainder);
        ($x, $x_old) = ($x_old ^ gf_multiply($quotient, $x), $x);
        ($y, $y_old) = ($y_old ^ gf_multiply($quotient, $y), $y);        
    }
    if (int($num) != 1) {
        return "NO MI. However, the GCD of $NUM and $MOD is: $num\n";
    } else {
        ($quotient, $remainder) = gf_divide($x_old ^ $MOD, $MOD, $n);
        return $remainder;
    }
}
