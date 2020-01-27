/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

struct sniff_ip { 
u_char  ip_vhl;					/* version << 4 | header length >> 2 */ 
u_char  ip_tos;					/* type of service */ 
u_short ip_len;					/* total length */ 
u_short ip_id;					/* identification */ 
u_short ip_off;					/* fragment offset field */ 
#define IP_RF 0x8000			/* reserved fragment flag */ 
#define IP_DF 0x4000			/* dont fragment flag */ 
#define IP_MF 0x2000			/* more fragments flag */ 
#define IP_OFFMASK 0x1fff		/* mask for fragmenting bits */ 
u_char  ip_ttl;					/* time to live */ 
u_char  ip_p;					/* protocol */ 
u_short ip_sum;					/* checksum */ 
struct  in_addr ip_src,ip_dst;	/* source and dest address */ 
}; 


struct sniff_tcp { 
u_short th_sport;				/* source port */ 
u_short th_dport;				/* destination port */ 
u_int th_seq;					/* sequence number */ 
u_int th_ack;					/* acknowledgement number */ 
u_char  th_offx2;				/* data offset, rsvd */ 
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4) 
u_char  th_flags; 
#define TH_FIN  0x01 
#define TH_SYN  0x02 
#define TH_RST  0x04 
#define TH_PUSH 0x08 
#define TH_ACK  0x10 
#define TH_URG  0x20 
#define TH_ECE  0x40 
#define TH_CWR  0x80 
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR) 
u_short th_win;					/* window */ 
u_short th_sum;					/* checksum */ 
u_short th_urp;					/* urgent pointer */ 
}; 


struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* Structure of a TCP header */
struct tcpheader {
 unsigned short int tcph_srcport;
 unsigned short int tcph_destport;
 unsigned int       tcph_seqnum;
 unsigned int       tcph_acknum;
 unsigned char      tcph_reserved:4, tcph_offset:4;
 u_char  th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4) 
};
/* IP Header */
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

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
      char * data;
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("         To: %s\n", inet_ntoa(ip->iph_destip)); 
//struct ipheader * ip =(struct ipheader *)(packet +sizeof(struct ethheader));


    /* determine protocol */
    switch(ip->iph_protocol) {                               
  case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
int sizeEthernet = 14;
int sizeIp= (ip-> iph_ihl)*4;



struct tcpheader *tcp = (struct tcpheader*)(packet + sizeEthernet +sizeIp);
int sizeTcp= TH_OFF(tcp)*4;

data= (unsigned char*)(packet + sizeEthernet +sizeIp +sizeTcp);
int sizeData = ntohs(ip->iph_len)-(sizeIp + sizeTcp);

for(int i=0; i<sizeData;i++){
	printf("%c",*(data+i));
} 
   return;
case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;

        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}
 
int main()
{

pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
//udp proto port 23
char filter_exp[] = "icmp proto port 1";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name eth3
// Students needs to change "eth3" to the name
// found on their own machines (using ifconfig).
handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
// Step 3: Capture packets

pcap_loop(handle, -1, got_packet, NULL);

pcap_close(handle); //Close the handle
return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
