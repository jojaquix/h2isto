//
// Created by jhon on 6/07/21.
//

#include <gtest/gtest.h>
#include <pcap/pcap.h>

#include "datatypes.h"
#include "stats/stats.h"


void generate_http_data(http_req_stats_t& http_req_stats) {
    http_req_stats["domain1.com"] =     110;
    http_req_stats["domain2.com"] =     120;
    http_req_stats["domain3.com"] =     80;
    http_req_stats["domain4.com"] =     10;
    http_req_stats["domain5.com"] =     2;
    http_req_stats["domain6.com"] =     20;
    http_req_stats["domain7.com"] =     11;
    http_req_stats["domain8.com"] =     11;
    http_req_stats["domain9.com"] =     109;
    http_req_stats["domain10.com"] =    20;
    http_req_stats["domain11.com"] =    110;
    http_req_stats["domain12.com"] =    60;
    http_req_stats["domain13.com"] =    15;

    //the sum is 678
}


TEST(basicTests, histogramTest)
{
    http_req_stats_t http_req_stats;
    generate_http_data(http_req_stats);
    http_req_histogram_t http_req_histogram;
    auto total = generate_histogram(http_req_stats, http_req_histogram);
    EXPECT_EQ(678, total);
    EXPECT_EQ(10, http_req_histogram.size());
    EXPECT_EQ("domain2.com", http_req_histogram[0].first);
    EXPECT_EQ(std::string("domain7.com"), http_req_histogram.back().first);
}



