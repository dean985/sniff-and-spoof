all: sniffer spoofer
	
sniffer: sniffer.c
	gcc sniffer.c -o sniff -lpcap

spoofer: spoofer.c
	gcc spoofer.c -o spoofer
	
sns: sniffandspoof.c
	gcc sniffandspoof.c -o sniffandspoof -lpcap
