#!/bin/bin/python

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(filter='icmp and src 10.0.2.15',prn=print_pkt)
