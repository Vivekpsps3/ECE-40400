#!/usr/bin/env perl

##  PrimeGenerator.pl
##  Author: Avi Kak
##  Date: February 26, 2016

##  Call syntax:
##
##        PrimeGenerator.pl  width_desired_for_bit_field_for_prime
##
##  For example, if you call
##
##        PrimeGenerator.pl 32
##
##  you may get a prime that looks like 3340094299.  On the other hand, if you
##  call
##
##        PrimeGenerator.pl 128
##
##  you may get a prime that looks like 333618953930748159614512936853740718827
##
##  IMPORTANT:  The two most significant are explicitly set for the prime that is
##              returned.

use strict;
use warnings;
use Math::BigInt;

############################  class PrimeGenerator  ##############################
package PrimeGenerator;                                                 

sub new {                                                                    #(A1)
    my ($class, %args) = @_;                                                 #(A2)
    bless {                                                                  #(A3)
        _bits  =>  int($args{bits}),                                         #(A4)
        _debug =>  $args{debug} || 0,                                        #(A5)
        _largest => (1 << int($args{bits})) - 1,                             #(A6)
    }, $class;                                                               #(A7)
}

sub set_initial_candidate {                                                  #(B1)
    my $self = shift;                                                        #(B2)
    my @arr = map {my $x = rand(1); $x > 0.5 ? 1 : 0 } 0 .. $self->{_bits}-4;#(B3)
    push @arr, 1;                                                            #(B4)
    unshift @arr, (1,1);                                                     #(B6)
    my $bstr = join '', split /\s/, "@arr";                                  #(B7)
#    $self->{candidate} = oct("0b".$bstr);                                   #(B8)
    $self->{candidate} = Math::BigInt->from_bin($bstr);                      #(B8)
}    

sub set_probes {                                                             #(C1)
    my $self = shift;                                                        #(C2)
    $self->{probes} = [2,3,5,7,11,13,17];                                    #(C3)
}

# This is the same primality testing function as shown earlier
# in Section 11.5.6 of Lecture 11:
sub test_candidate_for_prime_with_bigint {                                   #(D1)
    my $self = shift;                                                        #(D2)
    my $p = $self->{candidate};                                              #(D3)
    return 0 if $p->is_one();                                                #(D4)
    my @probes = @{$self->{probes}};                                         #(D5)
    foreach my $a (@probes) {                                                #(D6)
        $a = Math::BigInt->new("$a");                                        #(D7)
        return 1 if $p->bcmp($a) == 0;                                       #(D8)
        return 0 if $p->copy()->bmod($a)->is_zero();
    }
    my ($k, $q) = (0, $p->copy()->bdec());                                   #(D9)
    while (! $q->copy()->band( Math::BigInt->new("1"))) {                    #(D10)
        $q->brsft( 1 );                                                      #(D11)
        $k += 1;                                                             #(D12)
    }
    my ($a_raised_to_q, $a_raised_to_jq, $primeflag);                        #(D13)
    foreach my $a (@probes) {                                                #(D14)
        my $abig = Math::BigInt->new("$a");                                  #(D15)
        my $a_raised_to_q = $abig->bmodpow($q, $p);                          #(D16)
        next if $a_raised_to_q->is_one();                                    #(D17)
        my $pdec = $p->copy()->bdec();                                       #(D18)
        next if ($a_raised_to_q->bcmp($pdec) == 0) && ($k > 0);              #(D19)
        $a_raised_to_jq = $a_raised_to_q;                                    #(D20)
        $primeflag = 0;                                                      #(D21)
        foreach my $j (0 .. $k - 2) {                                        #(D22)
            my $two = Math::BigInt->new("2");                                #(D23)
            $a_raised_to_jq = $a_raised_to_jq->copy()->bmodpow($two, $p);    #(D24)
            if ($a_raised_to_jq->bcmp( $p->copy()->bdec() ) == 0 ) {         #(D25)
                $primeflag = 1;                                              #(D26)
                last;                                                        #(D27)
            }
        }
        return 0 if ! $primeflag;                                            #(D28)
    }
    my $probability_of_prime = 1 - 1.0/(4 ** scalar(@probes));               #(D29)
    $self->{probability_of_prime} = $probability_of_prime;                   #(D30)
    return $probability_of_prime;                                            #(D31)
}

sub findPrime {                                                              #(E1)
    my $self = shift;                                                        #(E2)
    $self->set_initial_candidate();                                          #(E3)
    print "        candidate is:  $self->{candidate}\n" if $self->{_debug};  #(E4)
    $self->set_probes();                                                     #(E5)
    print "        The probes are: @{$self->{probes}}\n" if $self->{_debug}; #(E6)
    my $max_reached = 0;                                                     #(E7)
    while (1) {                                                              #(E8)
        if ($self->test_candidate_for_prime_with_bigint()) {                 #(E9)
            print "Prime number:  $self->{candidate} with probability: " .
                  "$self->{probability_of_prime}\n" if $self->{debug};       #(E10)
            last;                                                            #(E11)
        } else {                                                             #(E12)
            if ($max_reached ) {                                             #(E13)
                $self->{candidate} -= 2;                                     #(E14)
            } elsif ($self->{candidate} >= $self->{_largest} - 2) {          #(E15)
                $max_reached = 1;                                            #(E16)
                $self->{candidate} -= 2;                                     #(E17)
            } else {                                                         #(E18)
                $self->{candidate} += 2;                                     #(E19)
            }
        }
    }
    return $self->{candidate};                                               #(E20)
}

1;
################################  main    ########################################
package main;

unless (@ARGV) {                                                             #(M1)
    1;                                                                       #(M2)
} else {                                                                     #(M3)
    my $bitfield_width = shift @ARGV;                                        #(M4)
    my $generator = PrimeGenerator->new(bits => $bitfield_width);            #(M5)                    
    my $prime = $generator->findPrime();                                     #(M6)
    print "Prime returned: $prime\n";                                        #(M7)
}
