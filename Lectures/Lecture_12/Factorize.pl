#!/usr/bin/env perl

##  Factorize.pl
##  Author: Avi Kak
##  Date: February 19, 2016 

##  Uncomment line (F12) and comment out line (F13) if you want to see the results
##  with the simpler form of the Pollard-Rho algorithm.

use strict;
use warnings;

die "\nUsage:   $0  <integer> \n" unless @ARGV == 1;                         #(A1)
my $p = shift @ARGV;                                                         #(A2)

die "Your number is too large for factorization by this script. " .
    "Instead, try the script 'FactorizeWithBigInt.pl'\n"
    if $p > 0x7f_ff_ff_ff;                                                   #(A3)

my @factors = @{factorize($p)};                                              #(A4)
my %how_many_of_each;                                                        #(A5)
map {$how_many_of_each{$_}++} @factors;                                      #(A6)
print "\nFactors of $p:\n";                                                  #(A7)
foreach my $factor (sort {$a <=> $b} keys %how_many_of_each) {               #(A8)
    print "    $factor ^ $how_many_of_each{$factor}\n";                      #(A9)
}                                           

sub factorize {                                                              #(F1)
    my $n = shift;                                                           #(F2)
    my @prime_factors = ();                                                  #(F3)
    my @factors;                                                             #(F4)
    push @factors, $n;                                                       #(F5)
    while (@factors > 0) {                                                   #(F6)
        my $p = pop @factors;                                                #(F8)
        if (test_integer_for_prime($p)) {                                    #(F9)
            push @prime_factors, $p;                                         #(F10)
            next;                                                            #(F11)
        }
#        my $d = pollard_rho_simple($p);                                     #(F12)
        my $d = pollard_rho_strong($p);                                      #(F13)
        if ($d == $p) {                                                      #(F14)
            push @factors, $d;                                               #(F15)
        } else {                   
            push @factors, $d;                                               #(F16)       
            push @factors, int($p / $d);                                     #(F17)
        }
    }
    return \@prime_factors;                                                  #(F18)
}

sub test_integer_for_prime {                                                 #(P1)
    my $p = shift;                                                           #(P2)
    my @probes = qw[ 2 3 5 7 11 13 17 ];                                     #(P3)
    foreach my $a (@probes) {                                                #(P4)
        return 1 if $a == $p;                                                #(P5)
    }
    my ($k, $q) = (0, $p - 1);                                               #(P6)
    while (! ($q & 1)) {                                                     #(P7)
        $q >>= 1;                                                            #(P8)
        $k += 1;                                                             #(P9)
    }
    my ($a_raised_to_q, $a_raised_to_jq, $primeflag);                        #(P10)
    foreach my $a (@probes) {                                                #(P11)
        my ($base,$exponent) = ($a,$q);                                      #(P12)
        my $a_raised_to_q = 1;                                               #(P13)
        while ((int($exponent) > 0)) {                                       #(P14)
            $a_raised_to_q = ($a_raised_to_q * $base) % $p 
                                              if int($exponent) & 1;         #(P15)
            $exponent = $exponent >> 1;                                      #(P16)
            $base = ($base * $base) % $p;                                    #(P17)
        }
        next if $a_raised_to_q == 1;                                         #(P18)
        next if ($a_raised_to_q == ($p - 1)) && ($k > 0);                    #(P19)
        $a_raised_to_jq = $a_raised_to_q;                                    #(P20)
        $primeflag = 0;                                                      #(P21)
        foreach my $j (0 .. $k - 2) {                                        #(P22)
            $a_raised_to_jq = ($a_raised_to_jq ** 2) % $p;                   #(P23)
            if ($a_raised_to_jq == $p-1) {                                   #(P24)
                $primeflag = 1;                                              #(P25)
                last;                                                        #(P26)
            }
        }
        return 0 if ! $primeflag;                                            #(P27)
    }
    my $probability_of_prime = 1 - 1.0/(4 ** scalar(@probes));               #(P28)
    return $probability_of_prime;                                            #(P29)
}
    
sub pollard_rho_simple {                                                     #(Q1)
    my $p = shift;                                                           #(Q2)
    my @probes = qw[ 2 3 5 7 11 13 17 ];                                     #(Q3)
    foreach my $a (@probes) {                                                #(Q4)
        return $a if $p % $a == 0;                                           #(Q5)
    }
    my $d = 1;                                                               #(Q6)
    my $a = 2 + int(rand($p));                                               #(Q7)
    my @random_num = ($a);                                                   #(Q8)
    while ($d == 1) {                                                        #(Q9)
        my $b = 2 + int(rand($p));                                           #(Q10)
        foreach my $a (@random_num) {                                        #(Q11)
            $d = gcd($a - $b, $p);                                           #(Q12)
            last if $d > 1;                                                  #(Q13)
        }
        push @random_num, $b;                                                #(Q14)
    }
    return $d;                                                               #(Q15)
}
    
sub pollard_rho_strong {                                                     #(R1)
    my $p = shift;                                                           #(R2)
    my @probes = qw[ 2 3 5 7 11 13 17 ];                                     #(R3)    
    foreach my $a (@probes) {                                                #(R4)
        return $a if $p % $a == 0;
    }
    my $d = 1;                                                               #(R5)
    my $a = 2 + int(rand($p));                                               #(R6)
    my $c = 2 + int(rand($p));                                               #(R6)
    my $b = $a;                                                              #(R7)
    while ($d == 1) {                                                        #(R8)
        $a = ($a * $a + $c) % $p;                                            #(R9)
        $b = ($b * $b + $c) % $p;                                            #(R10)
        $b = ($b * $b + $c) % $p;                                            #(R11)
        $d = gcd($a - $b, $p);                                               #(R12)
        last if $d > 1;                                                      #(R13)
    }
    return $d;                                                               #(R14)
}

sub gcd {                                                                    #(S1)
    my ($a,$b) = @_;                                                         #(S2)
    while ($b) {                                                             #(S3)
        ($a,$b) = ($b, $a % $b);                                             #(S4)
    }
    return $a;                                                               #(S5)
}
