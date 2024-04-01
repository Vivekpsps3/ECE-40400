#!/bin/sh
# Homework Number: HW09
# Name: Raghava Vivekananda Panchagnula
# ECN Login: rpanchag
# Due Date: 3/28/2024

# Flush and delete all previously defined rules and chains
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -t filter -F
sudo iptables -t raw -X
sudo iptables -F
sudo iptables -X

# Rule to accept packets originating from f1.com
# sudo iptables -A INPUT -p tcp -s f1.com -j ACCEPT
sudo iptables -A INPUT -s f1.com -j ACCEPT

# Change source IP address of outgoing packets to your machine's IP address
sudo iptables -t nat -A POSTROUTING -o wlo1 -j MASQUERADE

# Protect against indiscriminate and nonstop scanning of ports
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 500 -j ACCEPT

# Protect against SYN-flood Attack
sudo iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -m limit --limit 1/s --limit-burst 500 -j ACCEPT

# Allow full loopback access
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Port forwarding rule from port 8888 to port 25565
sudo iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination :25565

# Allow outgoing ssh connections to engineering.purdue.edu
sudo iptables -A INPUT -p tcp --dport 22 -s engineering.purdue.edu -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 --dst engineering.purdue.edu -m state --state NEW,ESTABLISHED -j ACCEPT

# Drop any other packets
sudo iptables -A INPUT -j DROP
sudo iptables -A OUTPUT -j DROP
sudo iptables -A FORWARD -j DROP

# sudo iptables -L

# # Clear any rules
# sudo iptables -t nat -F
# sudo iptables -t mangle -F
# sudo iptables -t filter -F
# sudo iptables -t raw -X
# sudo iptables -F
# sudo iptables -X
