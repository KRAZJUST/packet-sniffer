#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "arguments.h"
#include "packet_parser.h"
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <sstream>
#include <vector>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>


class PacketSniffer {
public:

    PacketSniffer(const Arguments& args);
    static void packet_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data);
    void start_sniffing();
    std::string set_filter() const;
    std::string set_port_filter() const;

private:

    // Create and instance of Arguments
    Arguments arguments;
    // Create an instance of PacketParser
    PacketParser parser;
};

#endif // PACKET_SNIFFER_H