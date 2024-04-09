#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <string>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <vector>

class Arguments {
public:
    std::string interface;
    bool tcp = false;
    bool udp = false;
    int port_destination = -1;
    int port_source = -1;
    bool icmp4 = false;
    bool icmp6 = false;
    bool arp = false;
    bool ndp = false;
    bool igmp = false;
    bool mld = false;
    int packets_num = 1;

    Arguments(int argc, char* argv[]);
    void parse_cmd_arguments(int argc, char* argv[]);
    static void print_help();
    void print_arguments() const;
    static void print_interfaces();
};

#endif // ARGUMENTS_H
