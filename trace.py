from scapy.all import *

a = IP()
a.dst = '54.239.34.171'
a.ttl = 11
b = ICMP()
send(a/b)
