// stats functions module is not a class that is
// reason does not start with uppercase.
// Created by jhon on 6/07/21.
//
//

#ifndef H2ISTO_STATS_H
#define H2ISTO_STATS_H

#include "datatypes.h"



uint32_t generate_histogram(http_req_stats_t& http_req_stats, http_req_histogram_t & http_req_histo);



#endif //H2ISTO_STATS_H
