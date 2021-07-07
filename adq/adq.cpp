//
// Created by jhon on 6/07/21.
//



#include <iostream>
#include "adq/adq.h"

#include <unistd.h>

//this could be a Class later check it

static char errbuf[PCAP_ERRBUF_SIZE];
static pcap_t* pcap_handle;
static struct bpf_program fp;		    /* The compiled filter expression */

//todo use a better bpf filter here for other http requests
//static char filter_exp[] = "(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420) and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)";	/* The filter expression */
static char filter_exp[] = "dst port 80";	/* The filter expression */
static bpf_u_int32 mask;		        /* The netmask of our sniffing device */
static bpf_u_int32 net;		            /* The IP of our sniffing device */


static void adq_got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);


void adq_init(char* dev) {
    //pcap_handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    pcap_handle = pcap_create(dev,errbuf);
    if(pcap_handle == nullptr) {
        std::cerr<<"error opening dev " << dev <<" " << errbuf << std::endl;
        exit(1);
    }

    if (pcap_set_buffer_size(pcap_handle, BUFSIZ) != 0) {
        std::cerr<<"error setting buffer"  << std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(1);
    }

    if (pcap_activate(pcap_handle) != 0) {
        std::cerr<<"error activating"  << std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(1);
    }

    if (pcap_setnonblock(pcap_handle, 1, errbuf) != 0) {
        std::cerr<<"error activating"  << std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(1);
    }

    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr<<"Couldn't parse filter "<< filter_exp <<" "<< pcap_geterr(pcap_handle) <<std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(2);
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr<<"Couldn't install filter "<< filter_exp <<" "<< pcap_geterr(pcap_handle) <<std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(3);
    }
    /*
    if (pcap_set_timeout(pcap_handle, 1)== -1) {
        std::cerr<<"Couldn't set time out" <<" "<< pcap_geterr(pcap_handle) <<std::endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        exit(4);
    }*/
}

void adq_deinit() {
    pcap_close(pcap_handle);
    pcap_handle = nullptr;
}

void adq_process_packet(http_req_stats_t& http_req_stats) {
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    //printf("pcap_next \n");

    //packet = pcap_next(pcap_handle, &header);
    int pcap_loop_ret = pcap_dispatch(pcap_handle, -1, (pcap_handler)adq_got_packet, nullptr);
    if (pcap_loop_ret == 0) {
        usleep(150*1000);
    }

    /* Print its length */
    //printf("Jacked a packet with length of [%d]\n", header.len);


}


static void adq_got_packet(u_char *args, const struct pcap_pkthdr *header,
                           const u_char *packet) {
    printf("Jacked a packet with length of [%d]\n", header->len);
}







