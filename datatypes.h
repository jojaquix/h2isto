//
// Created by jhon on 6/07/21.
//

#ifndef H2ISTO_DATATYPES_H_H
#define H2ISTO_DATATYPES_H_H


#include <string>
#include <vector>
#include <unordered_map>
#include <inttypes.h>


using http_counter_t = std::pair<std::string, uint32_t>;

// used during packet adq unordered_map sound good for that:
// http://supercomputingblog.com/windows/ordered-map-vs-unordered-map-a-performance-study/

using http_req_stats_t = std::unordered_map<std::string, uint32_t>;

// used for postprocessing stage a vector should be fine for now
using http_req_histogram_t = std::vector<http_counter_t>;


#endif //H2ISTO_DATATYPES_H_H
