//
// Created by jhon on 6/07/21.
//

#include "stats.h"
#include <algorithm>

// this algorithm is O(N)

uint32_t generate_histogram(http_req_stats_t& http_req_stats, http_req_histogram_t& http_req_histo) {


    http_req_histo.clear();

    std::copy(http_req_stats.begin(),
              http_req_stats.end(),
              std::back_inserter<std::vector<http_counter_t>>(http_req_histo));

    std::sort(http_req_histo.begin(), http_req_histo.end(),
              [](const http_counter_t &l, const http_counter_t &r)
              {
                  return l.second > r.second;
              });

    if(http_req_histo.size() >= 10) {
        http_req_histo.erase(http_req_histo.begin() + 10, http_req_histo.end());
    }

    //calc the sum
    uint32_t acc = 0;
    for(auto const& it : http_req_histo) {
        acc+= it.second;
    }


    return acc;
}
