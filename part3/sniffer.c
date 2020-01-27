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

/**
 * Struct of an ethernet header
 */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; // destination of host 
  u_char  ether_shost[ETHER_ADDR_LEN]; // source host address
  u_short ether_type;                  // ethernet type like IP protocol 
};




/**
 * Struct of an internet header
 * ihl - ip header length
 * tos - type of service
 * len - total length
 * ttl - time to live
 */

struct ipheader {
  unsigned char      iph_ihl:4, 
                     iph_ver:4; 
  unsigned char      iph_tos; 
  unsigned short int iph_len; 
  unsigned short int iph_ident; 
  unsigned short int iph_flag:3, 
                     iph_offset:13; 
  unsigned char      iph_ttl; 
  unsigned char      iph_protocol; 
  unsigned short int iph_chksum; 
  struct  in_addr    iph_sourceip;  
  struct  in_addr    iph_destip;   
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
