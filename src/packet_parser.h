#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

class PacketParser {
public:
    PacketParser(); // Constructor

    // Function to print packet information
    void print_packet(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data);
    void print_ipv4_info(const u_char* ip_packet_data);
    void print_ipv6_info(const u_char* ip_packet_data);
    void print_arp_info(const u_char* ip_packet_data);
    void print_timestamp(const struct pcap_pkthdr* pkthdr);
    const char* protocol_to_string(uint8_t protocol);

};

#endif // PACKET_PARSER_H
