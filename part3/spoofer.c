/**
 * (1) create a raw socket, 
 * (2) set socket option,
 * (3) construct thepacket,
 * (4) send out the packet through the raw socket
 */
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFF_SIZE 100

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type;        // ICMP message type
  unsigned char icmp_code;        // Error info
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4,         //IP header length
                     iph_ver:4;         //IP version
  unsigned char      iph_tos;           //Type of service
  unsigned short int iph_len;           //IP Packet length (data + header)
  unsigned short int iph_ident;         //Identification
  unsigned short int iph_flag:3,        //Fragmentation flags
                     iph_offset:13;     //Flags offset
  unsigned char      iph_ttl;           //Time to Live
  unsigned char      iph_protocol;      //Protocol type
  unsigned short int iph_chksum;        //IP datagram checksum
  struct  in_addr    iph_sourceip;      //Source IP address 
  struct  in_addr    iph_destip;        //Destination IP address 
};


void send_packet( struct ipheader *ip){
    struct sockaddr_in sin;
    int en = 1;

    int sck = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);         //socket creation
    setsockopt(sck, IPPROTO_IP, IP_HDRINCL, &en, sizeof(en)); // set socket FD's optionn

    // Now filling info about the destination
    sin.sin_family = AF_INET;
    sin.sin_addr = ip->iph_destip;

    // finally sending the packet
    sendto(sck, ip , ntohs(ip->iph_len), 0, (struct sockaddr *)(&sin), sizeof(sin));

    close(sck);

}

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

int main (){


    char *ipdest;
    char *ipsrc;

    char buff[1000];
    memset(buff, 0 ,1000);
    
    /////////// ICMP handling and config
    
    struct icmpheader *icmp = (struct icmpheader*)(buff + sizeof(struct ipheader));
    icmp->icmp_type = 8;                // ping request
   
    //checksum
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));



    ////////// IP header config
    struct ipheader *ip = (struct ipheader *)(buff);
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_destip.s_addr = inet_addr("160.153.129.23");
    ip->iph_sourceip.s_addr = inet_addr("10.0.2.5");
    ip->iph_ttl = 15;
    ip->iph_ihl = 5;
    ip->iph_ver = 4;

    /////////////Sending the packet
    struct sockaddr_in sin;
    int en = 1;

    int sck = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);         //socket creation
    setsockopt(sck, IPPROTO_IP, IP_HDRINCL, &en, sizeof(en)); // set socket FD's optionn

    // Now filling info about the destination
    sin.sin_family = AF_INET;
    sin.sin_addr = ip->iph_destip;

    // finally sending the packet
    sendto(sck, ip , ntohs(ip->iph_len), 0, (struct sockaddr *)(&sin), sizeof(sin));
    inet_ntop(AF_INET, &(sin.sin_addr), ipdest, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->iph_sourceip), ipsrc, INET_ADDRSTRLEN );
    close(sck);
    


     printf("+++++++++++++++++++++++++++++\n"
           "|          Spoofing           |\n"
           "|     The ping was sent to:   |\n"
           "|       %s       |\n"
           "|        Sent From:           |\n"
           "|       %s              |\n"
           "+++++++++++++++++++++++++++++\n", ipdest, ipsrc);

    return 0;
}
