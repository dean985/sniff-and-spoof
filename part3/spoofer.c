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
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
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


void send_ip_packet( struct ipheader *ip){
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



int main (){

    struct sockaddr_in sin;
    char *str = "   MESSAGE\n";
    // create socket
    int sck = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // filling info about the destenation
    memset((char *)&sin, 0, sizeof(sin));
    sin.sin_addr.s_addr = inet_addr("10.0.2.4");
    sin.sin_family = AF_INET;
    sin.sin_port = htons(5000);

    //sending
    sendto(sck, str, strlen(str), 0, (struct sockaddr*)&sin, sizeof(sin));
    close(sck);



    return 0;
}
