#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>


struct buffer{                                  // buffer and it's size
    unsigned short int *d;
    size_t l;
}


uint16_t chksum( unsigned char buf[], size_t buflen ){
    uint32_t sum = 0, i;                                // checksum, iterator
    if( buflen < 1 ) return 0;                          // if buffer is empty, exit
    for( i=0; i<buflen-1; i+=2 ) {
        sum += *(unsigned short int*)&buf[i];           // add all half-words together
    }  
    if( buflen & 1 ){
     sum += buf[buflen - 1];                            // if you missed last byte, add it
    }    
    return ~((sum >> 16) + (sum & 0xffff));             // fold high to low order word
                                                        // return 1's complement
}

int snd_frm_raw(char *iface, unsigned char dst[], struct buffer frm)
{
    struct ifreq ifidx = { 0 };                   // interface index
    struct sockaddr_ll trg_addr;                        // target address
    int    sd, i;                                       // raw socket descriptor

        
    /* make a raw socket */
    if((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {   
        perror("[-] Error! Cannot create raw socket");
        return -1;
    }

    /* Get the index of the interface to send on */
    strncpy(ifidx.ifr_name, iface, strlen(iface));      // set interface name
    
    if( ioctl(sd, SIOCGIFINDEX, &ifidx) < 0 ) {         // get interface index
        perror("[-] Error! Cannot get interface index");
        return -1;
    }

    trg_addr.sll_ifindex = ifidx.ifr_ifindex;           // interface index
    trg_addr.sll_halen   = ETH_ALEN;                    // address length
    
    for( i=0; i<6; ++i ) trg_addr.sll_addr[i] = dst[i]; // set target MAC address
    
    
    /* send spoofed packet (set routing flags to 0) */
    if(sendto(sd, frm.d, frm.l, 0, (struct sockaddr*)&trg_addr, sizeof(struct sockaddr_ll)) < 0) {
        perror("[-] Error! Cannot send spoofed frame");
        return -1;
    }
    else
        printf( "[+] Spoofed Ethernet frame sent successfully!\n");

    return 0;                                           // success!
}