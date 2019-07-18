#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void Print_Mac(u_int8_t * mac){

    printf(" %02x:%02x:%02x:%02x:%02x:%02x \n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

}

void Print_Ip(u_int8_t * ip){
    printf("%d.%d.%d.%d \n",ip[0],ip[1],ip[2],ip[3]);
}


void Print_Port(uint16_t * port_ptr) {
  uint16_t port = *port_ptr;
  //port = (uint16_t)((port << 8) | (port >> 8));
  port = ntohs(port);
  printf("%d \n ", port);

}

void Print_Data(uint8_t *data){
    printf("=============data===============\n");

    for(int i=0; i<10;i++){
    printf("%02x:",data[i]);
    }
}



struct Ether_Header{
    uint8_t srcmac[6];
    uint8_t dstmac[6];
    uint8_t type[2];
};

struct Ip_Header{
    uint8_t ip_vhl;
    uint8_t ip_tos;
    uint16_t ip_len;

    uint16_t ip_id;
    uint16_t ip_off;

    uint8_t ip_ttl;
    uint8_t ip_prot;
    uint16_t ip_sum;

    uint8_t ip_src[4];
    uint8_t ip_dst[4];

};

struct Tcp_Header{
    uint16_t tcp_srcport;
    uint16_t tcp_dstport;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_len;
    uint16_t tcp_win;
    uint16_t tcp_sum;
    uint16_t tcp_point;
};


//#define Ip(ip)  ((ip)->type & 0xFFFF)
#define Ipv4 0x0800
#define Ipv6 0x86DD
#define TcpProt 0x06

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {

  if (argc != 2) {
    usage();
    return -1;
  }


  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;



    struct Ether_Header *eth = (struct Ether_Header *)packet;
    struct Ip_Header *ip = (struct Ip_Header *)(packet + 14);
    struct Tcp_Header *tcp = (struct Tcp_Header *)(packet + 34);
    uint8_t *payload = (uint8_t *)tcp+sizeof (Tcp_Header);


    printf("========== Ether Header ========= \n");
    printf("SrcMac : ");
    Print_Mac(eth->srcmac);
    printf("DstMac : ");
    Print_Mac(eth->dstmac);

    if(((eth->type[0]<<8)|eth->type[1]) == Ipv4){
        printf("========== Ip Header ============ \n");

        printf("SrcIp : ");
        Print_Ip(ip->ip_src);
        printf("DstIp : ");
        Print_Ip(ip->ip_dst);

        if(ip->ip_prot == TcpProt){
            printf("========= Tcp Header ============ \n");
            printf("SrcPort : ");
            Print_Port(&tcp->tcp_srcport);
            printf("DstPort : ");
            Print_Port(&tcp->tcp_dstport);

            if(*payload != NULL){
                Print_Data(payload);
                printf("\n");
            }
        }

    }
     printf("=================================\n");
     printf("\n");
     printf("\n");
   }

  pcap_close(handle);
  return 0;
}


