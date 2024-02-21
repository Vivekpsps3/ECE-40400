#!/usr/bin/env perl

##  FactorizeWithBigInt.pl
##  Author: Avi Kak
##  Date: February 21, 2016 

##  Uncomment line (F13) and comment out line (F14) if you want to see the results
##  with the simpler form of the Pollard-Rho algorithm.

use strict;
use warnings;
use Math::BigInt;                      
use Math::BigInt::Random::OO;          

###########################  class FactorizeWithBigInt  ##########################
package FactorizeWithBigInt;

sub new {                                                                    #(A1)
    my ($class, $num) = @_;                                                  #(A2)
    bless {                                                                  #(A3)
        num  =>  int($num),                                                  #(A4)
    }, $class;                                                               #(A5)
}

sub factorize {                                                              #(F1)
    my $self = shift;                                                        #(F2)
    my $n = $self->{num};                                                    #(F3)
    my @prime_factors = ();                                                  #(F4)
    my @factors;                                                             #(F5)
    push @factors, $n;                                                       #(F6)
    while (@factors > 0) {                                                   #(F7)
        my $p = pop @factors;                                                #(F8)
        if ($self->test_integer_for_prime($p)) {                             #(F9)
            my $pnum = $p->numify();                                         #(F10)
            push @prime_factors, $p;                                         #(F11)
            next;                                                            #(F12)
        }
#       my $d = $self->pollard_rho_simple($p);                               #(F13)
        my $d = $self->pollard_rho_strong($p);                               #(F14)
        if ($d->copy()->bacmp($p->copy()) == 0) {                            #(F15)
            push @factors, $d;                                               #(F16)
        } else {                                                             #(F17)
            push @factors, $d;                                               #(F18)
            my $div = $p->copy()->bdiv($d->copy());                          #(F19)
            push @factors, $div;                                             #(F20)
        }
    }
    return \@prime_factors;                                                  #(F21)
}

sub test_integer_for_prime {                                                 #(P1)
    my $self = shift;                                                        #(P2)
    my $p = shift;                                                           #(P3)
    return 0 if $p->is_one();                                                #(P4)
    my @probes = qw[ 2 3 5 7 11 13 17 ];                                     #(P5)
    foreach my $a (@probes) {                                                #(P6)
        $a = Math::BigInt->new("$a");                                        #(P7)
        return 1 if $p->bcmp($a) == 0;                                       #(P8)
        return 0 if $p->copy()->bmod($a)->is_zero();                         #(P9)
    }
    my ($k, $q) = (0, $p->copy()->bdec());                                   #(P10)
    while (! $q->copy()->band( Math::BigInt->new("1"))) {                    #(P11)
        $q->brsft( 1 );                                                      #(P12)
        $k += 1;                                                             #(P13)
    }
    my ($a_raised_to_q, $a_raised_to_jq, $primeflag);                        #(P14)
    foreach my $a (@probes) {                                                #(P15)
        my $abig = Math::BigInt->new("$a");                                  #(P16)
        my $a_raised_to_q = $abig->bmodpow($q, $p);                          #(P17)
        next if $a_raised_to_q->is_one();                                    #(P18)
        my $pdec = $p->copy()->bdec();                                       #(P19)
        next if ($a_raised_to_q->bcmp($pdec) == 0) && ($k > 0);              #(P20)
        $a_raised_to_jq = $a_raised_to_q;                                    #(P21)
        $primeflag = 0;                                                      #(P22)
        foreach my $j (0 .. $k - 2) {                                        #(P23)
            my $two = Math::BigInt->new("2");                                #(P24)
            $a_raised_to_jq = $a_raised_to_jq->copy()->bmodpow($two, $p);    #(P25)
            if ($a_raised_to_jq->bcmp( $p->copy()->bdec() ) == 0 ) {         #(P26)
                $primeflag = 1;                                              #(P27)
                last;                                                        #(P28)
            }
        }
        return 0 if ! $primeflag;                                            #(P29)
    }
    my $probability_of_prime = 1 - 1.0/(4 ** scalar(@probes));               #(P30)
    return $probability_of_prime;                                            #(P31)
}
    
sub pollard_rho_simple {                                                     #(Q1)
    my $self = shift;                                                        #(Q2)
    my $p = shift;                                                           #(Q3)
    my @probes = qw[ 2 3 5 7 11 13 17 ];                                     #(Q4)
    foreach my $a (@probes) {                                                #(Q5)
        my $abig = Math::BigInt->new("$a");                                  #(Q6)
        return $abig if $p->copy()->bmod($abig)->is_zero();                  #(Q7)
    }
    my $d = Math::BigInt->bone();                                            #(Q8)
    my $randgen = Math::BigInt::Random::OO->new( max => $p );                #(Q9)
    my $a = Math::BigInt->new();                                             #(Q10)
    unless ($a->numify() >= 2) {                                             #(Q11)
        $a =  $randgen->generate(1);                                         #(Q12)
    }
    my @random_num = ($a);                                                   #(Q13)
    while ($d->is_one()) {                                                   #(Q14)
        my $b = Math::BigInt->new();                                         #(Q15)
        unless ($b->numify() >= 2) {                                         #(Q16)
            $b =  $randgen->generate(1);                                     #(Q17)
        }
        foreach my $a (@random_num) {                                        #(Q18)
            $d = Math::BigInt::bgcd($a->copy()->bsub($b),$p);                #(Q19)
            last if $d->bacmp(Math::BigInt->bone()) > 0;                     #(Q20)
        }
        push @random_num, $b;                                                #(Q21)
    }
    return $d;                                                               #(Q22)
}
    
sub pollard_rho_strong {                                                     #(R1)
    my $self = shift;                                                        #(R2)
    my $p = shift;                                                           #(R3)
    my @probes = qw[ 2 3 5 7 11 13 17 ];                                     #(R4)
    foreach my $a (@probes) {                                                #(R5)
        my $abig = Math::BigInt->new("$a");                                  #(R6)
        return $abig if $p->copy()->bmod($abig)->is_zero();                  #(R7)
    }
    my $d = Math::BigInt->bone();                                            #(R8)
    my $randgen = Math::BigInt::Random::OO->new( max => $p );                #(R9)
    my $a = Math::BigInt->new();                                             #(R10)
    unless ($a->numify() >= 2) {                                             #(R11)
        $a =  $randgen->generate(1);                                         #(R12)
    }
    $randgen = Math::BigInt::Random::OO->new( max => $p );                   #(R13)
    my $c = Math::BigInt->new();                                             #(R14)
    unless ($c->numify() >= 2) {                                             #(R15)
        $c =  $randgen->generate(1);                                         #(R16)
    }
    my $b = $a->copy();                                                      #(R17)
    while ($d->is_one()) {                                                   #(R18)
        $a->bmuladd($a->copy(), $c->copy())->bmod($p);                       #(R19)
        $b->bmuladd($b->copy(), $c->copy())->bmod($p);                       #(R20)
        $b->bmuladd($b->copy(), $c->copy())->bmod($p);                       #(R21)
        $d = Math::BigInt::bgcd( $a->copy()->bsub($b), $p );                 #(R22)
        last if $d->bacmp(Math::BigInt->bone()) > 0;                         #(R23)
    }
    return $d;                                                               #(R24)
}

#################################   main    ######################################
package main;

unless (@ARGV) {                                                             #(M1)
    1;                                                                       #(M2)
} else {                                                                     #(M3)
    my $p = shift @ARGV;                                                     #(M2)
    $p = Math::BigInt->new( "$p" );                                          #(M3)
    my $factorizer = FactorizeWithBigInt->new($p);                           #(M4)
    my @factors = @{$factorizer->factorize()};                               #(M5)
    my %how_many_of_each;                                                    #(M6)
    map {$how_many_of_each{$_}++} @factors;                                  #(M7)
    print "\nFactors of $p:\n";                                              #(M8)
    foreach my $factor (sort {$a <=> $b} keys %how_many_of_each) {           #(M9)
        print "    $factor ^ $how_many_of_each{$factor}\n";                  #(M10)
    }                                           
}
