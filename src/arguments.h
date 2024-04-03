#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <string>
#include <iostream>
#include <cstring>

class Arguments {
public:
    std::string interface;
    bool tcp = false;
    bool udp = false;
    int port_destination = 23;
    int port_source = 23;
    bool icmp4 = false;
    bool icmp6 = false;
    bool arp = false;
    bool ndp = false;
    bool igmp = false;
    bool mld = false;
    int packets_num = 1;

    Arguments(int argc, char* argv[]);
    void parse_cmd_arguments(int argc, char* argv[]);
    void print_help();
    void print_arguments();
};

#endif // ARGUMENTS_H
