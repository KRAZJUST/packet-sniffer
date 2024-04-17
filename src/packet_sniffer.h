#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "arguments.h"
#include "packet_parser.h"
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstdio>
#include <sstream>
#include <vector>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <csignal>
#include <atomic>


class PacketSniffer {
public:

    PacketSniffer(const Arguments& args);
    ~PacketSniffer();
    static void packet_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data);
    void start_sniffing();
    std::string set_filter() const;
    std::string set_port_filter() const;

private:
    pcap_t* pcap_handle;
    // Create and instance of Arguments
    Arguments arguments;
    // Static pointer to hold the PacketSniffer instance
    static PacketSniffer* global_packet_sniffer_instance;

    pcap_t* get_pcap_handle() const;
    static void signal_handler(int signum);
};

#endif // PACKET_SNIFFER_H