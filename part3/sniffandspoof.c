#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <netinet/in.h>


/**
 * Struct of an ethernet header
 */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; // destination of host 
  u_char  ether_shost[ETHER_ADDR_LEN]; // source host address
  u_short ether_type;                  // ethernet type like IP protocol 
};

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

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
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

unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}


void spoof_reply(struct ipheader* ip ){
    int en = 1;
    struct sockaddr_in dst;
    // creating the socket
    int sck = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    setsockopt(sck, IPPROTO_IP, IP_HDRINCL, &en, sizeof(en));

    // info about destination
    dst.sin_family = AF_INET;
    dst.sin_addr = ip->iph_destip;
    
    // sending the packet
    if (sendto(sck, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dst, sizeof(dst)) <0){
        printf("Problem with packet sending\n");
    }
    close(sck);
    printf("Spoofed packet SENT \n");
}







void got_packet( u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    printf("Captured packet\n");
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x800){     // 0x800 ethernet type IP
	    struct ipheader *ip = (struct ipheader*)(packet + sizeof(struct ethheader));
      struct tcpheader *tcp = (struct tcpheader*)(packet +sizeof(struct ethheader) + ip->iph_len*4);
	    printf("		source: %s\n", inet_ntoa(ip->iph_sourceip));
	    printf("		dest  : %s\n", inet_ntoa(ip->iph_destip));


      if (ip->iph_protocol == IPPROTO_ICMP){

        struct icmpheader *icmp = (struct icmpheader *)(packet +sizeof(struct ethheader)+ ip->iph_len*4);
        if (icmp->icmp_type != 8){      // if it's not ping request
            return;
        }
        printf("\n Protocol- ICMP\n");
        printf("   Dest port: %d\n", (int)(ntohs(tcp->tcp_sport)));
        printf("   Src port : %d\n", (int)(ntohs(tcp->tcp_dport)));
        
        //size_t PACKET_LEN = header->len; 
        size_t PACKET_LEN = 100;
        char buff[PACKET_LEN];
        memset(buff, 0, PACKET_LEN);
        memcpy((char *)buff, ip, ntohs(ip->iph_len));
        //////// cnstructing new ip header
        struct ipheader* new_ip = (struct ipheader*)buff;

        new_ip->iph_ttl = 15;
        new_ip->iph_sourceip = ip->iph_destip;
        new_ip->iph_destip = ip->iph_sourceip;

      ///////////// constructing new icmp header
        struct icmpheader* new_icmp = (struct icmpheader*)(buff+ (ip->iph_ihl *4));

        new_icmp->icmp_type = 0;
        new_icmp->icmp_chksum = 0;
        new_icmp->icmp_chksum = in_cksum((unsigned short *)new_icmp, sizeof(struct icmpheader));

        spoof_reply(new_ip);
      }
    }
}

int main(){
  pcap_t *handle;
  char error_buf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  handle = pcap_open_live("enp0s3",512, 1, 100, error_buf );
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);
  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle);


  return 0;
}
    
