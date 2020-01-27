sniffer2: sniffer2.c
	gcc sniffer2.c -o sniffer2
sniffer1: sniffer.c
	gcc sniffer.c -o sniff1 -lpcap
