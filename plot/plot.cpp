//
// Created by jhon on 6/07/21.
//

#include "plot/plot.h"
#include <iostream>
#include <iomanip>
#include <sys/ioctl.h> //ioctl() and TIOCGWINSZ
#include <unistd.h> // for STDOUT_FILENO




void plot_histogram(http_req_histogram_t& http_req_histogram, uint32_t total) {
    struct winsize size;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
    auto cols = size.ws_col;
    int histo_cols = cols ? cols : 100;
    histo_cols*=0.6;
    std::cout << "Total http requests: " <<total << std::endl;
    for (auto const& item : http_req_histogram) {
        std::cout <<std::setw(20) << item.first <<" "<<std::setw(20)<< item.second <<" ";
        uint16_t item_cols = (float(histo_cols)*float(item.second)/total);
        std::string line(item_cols, '*');
        std::cout << std::right << line << std::endl;

    }

}

