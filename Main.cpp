//
// Created by jhon on 6/07/21.
//

#include <iostream>
#include <ctime>
#include "adq/adq.h"
#include "plot/plot.h"
#include "stats/stats.h"



int main(int argc, char *argv[]) {
    adq_init();
    http_req_stats_t http_req_stats;
    auto secs = atoi(argv[1]);
    time_t now = time(nullptr);

    while (time(nullptr) < now + secs) {
        adq_process_packet(http_req_stats);
    }

    adq_deinit();

    http_req_histogram_t http_req_histogram;
    auto total = generate_histogram(http_req_stats, http_req_histogram);
    plot_histogram(http_req_histogram, total);

    std::cout << "Bye!!!" << std::endl;

    return 0;
}

