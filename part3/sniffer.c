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

#define IP_HL(ip)               (((ip)->iph_ihl) & 0x0f)
// #define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
    #define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

      int i;
      const u_char *ch;

      /* offset */
      printf("%05d   ", offset);
      
      /* hex */
      ch = payload;
      for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
          printf(" ");
      }
      /* print space to handle line less than 8 bytes */
      if (len < 8)
        printf(" ");
      
      /* fill hex gap with spaces if not full line */
      if (len < 16) {
        int gap = 16 - len;
        for (i = 0; i < gap; i++) {
          printf("   ");
        }
      }
      printf("   ");
      
      /* ascii (if printable) */
      ch = payload;
      for(i = 0; i < len; i++) {
        if (isprint(*ch))
          printf("%c", *ch);
        else
          printf(".");
        ch++;
      }

      printf("\n");

return;
}

void print_data(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;


		/* shift pointer to remaining bytes to print */

		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
    
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}


void got_packet( u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    printf("Captured packet\n");
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x800){     // 0x800 ethernet type IP
	    struct ipheader *ip = (struct ipheader*)(packet + sizeof(struct ethheader));
      struct tcpheader *tcp = (struct tcpheader*)(packet +sizeof(struct ethheader) + IP_HL(ip)*4);
	    printf("		source: %s\n", inet_ntoa(ip->iph_sourceip));
	    printf("		dest  : %s\n", inet_ntoa(ip->iph_destip));


      if (ip->iph_protocol == IPPROTO_ICMP){
        printf("   Protocol- ICMP\n");
      }
      if (ip->iph_protocol == IPPROTO_TCP){
        printf("   Protocol- TCP\n");
        printf("   Dest port: %d\n", (int)(ntohs(tcp->tcp_sport)));
        printf("   Src port : %d\n", (int)(ntohs(tcp->tcp_dport)));
        if ((int)(ntohs(tcp->tcp_dport)) == 23 || (int)(ntohs(tcp->tcp_sport)) == 23){
            int size_tcp = TH_OFF(tcp)*4;
            int size_ethernet = sizeof(struct ethheader);
            int size_ip = IP_HL(ip)*4;
            int size_data = ntohs(ip->iph_len) - (size_ip + size_tcp);
            const u_char* data = (unsigned char*)( packet + size_ethernet + size_ip +size_tcp );
            printf(" Data size : %d bytes", size_data);
            print_data(data, size_data);
        }
      }
    }
    
}

int main(){

   printf("+-------------------------------------------------+\n"
          "|                Computer Networks                |\n"
          "|           Packet Sniffing and Spoofing          |\n"
          "|                                                 |\n"
          "+-------------------------------------------------+\n\n"        
   );
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //char filter_exp[] = "ip proto icmp";               //For 2.1b first question
    char filter_exp[] = "ip proto tcp portrange 10-100"; //For 2.1b second question
    bpf_u_int32 net;

  /**
   * Step 1: Open live pcap sessionon NIC with enp03
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
