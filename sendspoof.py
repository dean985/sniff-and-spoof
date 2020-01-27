from scapy.all import *

a = IP()
a.src = '12.34.56.78' # My new IP address :)
a.dst = '10.0.2.15'
b = ICMP()
p = a/b
send(p)
