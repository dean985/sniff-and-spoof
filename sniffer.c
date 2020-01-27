#include <pcap.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <stdio.h>


struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; // destination of host 
  u_char  ether_shost[ETHER_ADDR_LEN]; // source host address
  u_short ether_type;                  // IP? ARP? RARP? etc 
};

struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void got_packet( u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    printf("Got a packet\n");
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x800){
	    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
	    printf("		Source: %s\n", inet_ntoa(ip->iph_sourceip));
	    printf("		Destination: %s\n", inet_ntoa(ip->iph_destip));
    }
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;

/**
 * Step 1: Open live pcap sessionon NIC with name eth3
 *          students need to change "eth3" to the name 
 *          found on their own machines, using ifconfig
 */
handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

/**
 * Step 2: compile filter_exp into bpf pseudo-code
 */
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);

// Step 3: capture packets
pcap_loop(handle, -1, got_packet, NULL);

pcap_close(handle);     //close handle

return 0;
}
// example for compilation - gcc -o sniff sniff.c -lpcap
