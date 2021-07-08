//
// Created by jhon on 6/07/21.
//

#include <iostream>
#include <ctime>

#include <glog/logging.h>

#include "adq/adq.h"
#include "plot/plot.h"
#include "stats/stats.h"
#include  "ketopt.h"


#include <sys/stat.h>

//for more complex maybe a data type later
static int secs = 10;
static std::string iface;
static std::string logp = "logs";

void show_usage();

/**
 * this parse the command line args and exit if there are not enough
 * @param argc
 * @param argv
 */
void parce_command_line_args(int argc, char *argv[]);

/**
 * init logging
 * @param logp log path to store logs
 */
void log_init();


int main(int argc, char *argv[]) {


    log_init();
    parce_command_line_args(argc, argv);

    adq_init(iface);
    http_req_stats_t http_req_stats;
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


void parce_command_line_args(int argc, char *argv[]) {

    static ko_longopt_t longopts[] = {
            {"logp",  ko_required_argument, 300},
            {"secs",  ko_required_argument, 301},
            {"iface", ko_required_argument, 302},
            {"help",  ko_no_argument,       303},
            {NULL, 0,                       0}
    };


    if (argc < 2) {
        show_usage();
        exit(EXIT_SUCCESS);
    }

    ketopt_t opt = KETOPT_INIT;
    int i, c;
    while ((c = ketopt(&opt, argc, argv, 1, "", longopts)) >= 0) {
        if (c == 300) { logp = opt.arg ? opt.arg : "logs"; }
        else if (c == 301) { secs = opt.arg ? atoi(opt.arg) : 10; }
        else if (c == 302) { iface = opt.arg ? opt.arg : ""; }
        else if (c == 303) {
            show_usage();
            exit(EXIT_SUCCESS);
        } else if (c == '?') {
            std::cerr << "unknown option ";
            std::cerr << char(opt.opt? opt.opt : ':') << std::endl;
            show_usage();
            exit(EXIT_SUCCESS);
        } else if (c == ':') {
            std::cerr << "missing args   ";
            std::cerr << char(opt.opt? opt.opt : ':') << std::endl;
            show_usage();
            exit(EXIT_SUCCESS);
        }
    }
}

void log_init() {

    struct stat st = {0};
    if (stat(logp.c_str(), &st) == -1) {
        mkdir(logp.c_str(), 0700);
    }

    if (!logp.empty()) {
        FLAGS_log_dir = logp;
    }

    google::InitGoogleLogging("h2isto");

    LOG(INFO) << "Logging initialized";
}

void show_usage() {
    std::cout << std::endl;
    std::cout << "h2isto is a symple http request counter" << std::endl;
    std::cout << std::endl;
    std::cout << "./h2isto --secs secs <other_options>" << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "other options:" << std::endl;
    std::cout << "--secs secs to capture" << std::endl;
    std::cout << std::endl;
    std::cout << "--logp logs directory (default logs) " << std::endl;
    std::cout << std::endl;
    std::cout << "--iface network interface name to monitor (if not default)" << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "jojaquix" << std::endl;
}

