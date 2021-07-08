//
// Created by jhon on 6/07/21.
// Portions for this adq module comes from https://www.tcpdump.org/pcap.html

#include <iostream>
#include "adq/adq.h"

#include <unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};



//this could be a Class later check it
static char errbuf[PCAP_ERRBUF_SIZE];
static pcap_t* pcap_handle;
static struct bpf_program fp;

//todo use a better bpf filter here for other http requests
static char filter_exp[] = "(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)";	/* The filter expression */
//static char filter_exp[] = "tcp";	    /* The filter expression */
static bpf_u_int32 mask;		        /* The netmask of our sniffing device */
static bpf_u_int32 net;		            /* The IP of our sniffing device */
static int fd; /* for select */


/* prototypes */
static void adq_got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/* implementation */

void adq_init(std::string dev) {

    if(dev.empty()) {
        dev = pcap_lookupdev(errbuf);
    }

    pcap_handle  = pcap_open_live(dev.c_str(), SNAP_LEN, 0, 1000, errbuf);
    if(pcap_handle == nullptr) {
        std::cerr<<"error opening dev " << dev <<" " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1) {
        std::cerr<<"error getting netmask" << std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(EXIT_FAILURE);
    }

    if (pcap_setnonblock(pcap_handle, 1, errbuf) != 0) {
        std::cerr<<"error setting nonblocking"  << std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(EXIT_FAILURE);
    }


    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr<<"Couldn't parse filter "<< filter_exp <<" "<< pcap_geterr(pcap_handle) <<std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr<<"Couldn't install filter "<< filter_exp <<" "<< pcap_geterr(pcap_handle) <<std::endl;
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(EXIT_FAILURE);
    }


    if (pcap_set_timeout(pcap_handle, 1)== -1) {
        std::cerr<<"Couldn't set time out" <<" "<< pcap_geterr(pcap_handle) <<std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(EXIT_FAILURE);
    }

    /* print capture info */
    printf("Device: %s\n", dev.c_str());
    printf("Filter expression: %s\n", filter_exp);



}

void adq_deinit() {
    pcap_freecode(&fp);
    pcap_close(pcap_handle);
    pcap_handle = nullptr;
}

void adq_process_packet(http_req_stats_t& http_req_stats) {

    int ret = pcap_dispatch(pcap_handle, -1, (pcap_handler)adq_got_packet, (u_char*)&http_req_stats);

    switch (ret) {
        case 0:
            usleep(150*1000);
            break;
        case -1 :
            std::cerr << "pcap_dispach error.";
            exit(EXIT_FAILURE);
            break;
        case -2 :
            std::cout << "pcap packet process break request";
            return;
            break;
    }
}


static void adq_got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    static int count = 1;                   /* packet counter */


    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    //getting stats
    http_req_stats_t * http_req_stats = (http_req_stats_t *) args;

    int size_ip;
    int size_tcp;
    int size_payload;

    //printf("\nPacket number %d with length of [%d]:\n", count, header->len);
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        //printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    std::string ip_srcs(inet_ntoa(ip->ip_src));
    std::string ip_dsts(inet_ntoa(ip->ip_dst));

    /* print source and destination IP addresses */
    //printf("       From: %s\n", ip_srcs.c_str());
    //printf("         To: %s\n", ip_dsts.c_str());

    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            //printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            //printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            //printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            //printf("   Protocol: IP\n");
            return;
        default:
            //printf("   Protocol: unknown\n");
            return;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        //printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    //printf("   Src port: %d\n", ntohs(tcp->th_sport));
    //printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    /* define/compute tcp payload (segment) offset */
    payload = (const char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
       //printf("   Payload (%d bytes):\n", size_payload);
    }

    (*http_req_stats)[ip_dsts]++;

}







