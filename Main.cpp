//
// Created by jhon on 6/07/21.
//

#include <iostream>
#include <ctime>
#include "adq/adq.h"



int main(int argc, char *argv[]) {

    adq_init("enp0s3");
    http_req_stats_t http_req_stats;
    auto secs = atoi(argv[1]);
    time_t now = time(nullptr);
    while (time(nullptr) < now + secs) {
        adq_process_packet(http_req_stats);
    }


    std::cout << "Bye!!!" << std::endl;
    adq_deinit();

    return 0;
}

