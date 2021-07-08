//
// Created by jhon on 6/07/21.
//

#ifndef H2ISTO_ADQ_H
#define H2ISTO_ADQ_H

#include "datatypes.h"

#include<errno.h>
#include <pcap.h>


void adq_init(std::string dev = "");
void adq_deinit();

/**
 * process next packet and check if is a request
 * to add to http_req_stats
 * @param http_req_stats
 */
void adq_process_packet(http_req_stats_t& http_req_stats);


#endif //H2ISTO_ADQ_H
