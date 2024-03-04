#!/usr/bin/env perl

### port_scan.pl
### Avi Kak  (kak@purdue.edu)

use strict;                                                
use warnings;
use IO::Socket;                                            

##  Usage example:
##
##          port_scan.pl  moonshine.ecn.purdue.edu   1  1024
##  or
##
##          port_scan.pl  128.46.144.123   1   1024

##  See the comment block for the Python version of the scirpt.  All of
##  those comments apply here also.


die "Usage: 'port_scan.pl  host  start_port  end_port' " .
    "\n where \n host is the symbolic hostname or the IP address of the " .
    "\n machine whose ports you want to scan, start_port is the starting " .
    "\n port number and end_port is the ending port number"
     unless @ARGV == 3;                                    

my $verbosity = 0;    # set it to 1 if you want to see the results for each  #(1)
                      # port separately as the scan is taking place
my $dst_host = shift;                                                        #(2)
my $start_port = shift;                                                      #(3)
my $end_port = shift;                                                        #(4)

my @open_ports = ();                                                         #(5)

# Autoflush the output supplied to print
$|++;                                                                        #(6)

# Scan the ports in the specified range:
for (my $testport=$start_port; $testport <= $end_port; $testport++) {        #(7)
    my $sock = IO::Socket::INET->new(PeerAddr => $dst_host,                  #(8)
                                     PeerPort => $testport,                  #(9)
                                     Timeout  => "0.1",                      #(10)
                                     Proto => 'tcp');                        #(11)
    if ($sock) {                                                             #(12)
        push @open_ports, $testport;                                         #(13)
        print "Open Port: ", $testport, "\n" if $verbosity == 1;             #(14)
        print  " $testport " if $verbosity == 0;                             #(15)
    } else {                                                                 #(16)
        print "Port closed: ", $testport, "\n" if $verbosity == 1;           #(17)
        print "." if $verbosity == 0;                                        #(18)
    }
}

# Now scan through the /etc/services file, if available, so that we can
# find out what services are provided by the open ports.  The goal here
# is to create a hash whose keys are the port names and the values
# the corresponding lines from the file that are "cleaned up" for
# getting rid of unwanted space:
my %service_ports;                                                           #(19)
if (-s "/etc/services" ) {                                                   #(20)
    open IN, "/etc/services";                                                #(21)
    while (<IN>) {                                                           #(22)
        chomp;                                                               #(23)
        # Get rid of the comment lines in the file:
        next if $_ =~ /^\s*#/;                                               #(24)
        my @entry = split;                                                   #(25)
        $service_ports{ $entry[1] } = join " ",split /\s+/, $_  if $entry[1];#(26)
    }
    close IN;                                                                #(27)
}

# Now find out what services are provided by the open ports. CAUTION: 
# This information is useful only when you are sure that the target
# machine has used the designated ports for the various services.
# That is not always the case for intra-networkds:
open OUT, ">openports.txt"
         or die "Unable to open openports.txt: $!";                          #(28)
if (!@open_ports) {                                                          #(29)
    print "\n\nNo open ports in the range specified\n";                      #(30)
} else {                                                                     #(31)
    print "\n\nThe open ports:\n\n";                                         #(32)
    foreach my $k (0..$#open_ports) {                                        #(33)
        if (-s "/etc/services" ) {                                           #(34)
            foreach my $portname ( sort keys %service_ports ) {              #(35)
                if ($portname =~ /^$open_ports[$k]\//) {                     #(36)
                    print "$open_ports[$k]:    $service_ports{$portname}\n"; #(37)
                }                                               
            }
        } else {                                                
            print $open_ports[$k], "\n";                                     #(38)
        }
        print OUT $open_ports[$k], "\n";                                     #(39)
    }
}
close OUT;                                                                   #(40)
