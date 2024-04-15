#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>
#include <vector>
#include <ctime>

class PacketParser {
public:
    PacketParser(); // Constructor

    // Function to print packet information
    void print_packet(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data);
    static void print_ipv4_info(const u_char* ip_packet_data);
    void print_ipv6_info(const u_char* ip_packet_data);
    static void print_arp_info(const u_char* ip_packet_data, const struct pcap_pkthdr* pkthdr);
    static void print_timestamp(const struct pcap_pkthdr* pkthdr);
    static const char* protocol_to_string(uint8_t protocol, int ipv_num);
    static void print_byte_offset(const u_char* data, unsigned int length);
    std::string format_ipv6_address(const std::string& ipv6_address);
    static void print_icmpv4_info(const u_char* icmp_packet_data);
    static void print_icmpv6_info(const u_char* icmpv6_packet_data);
    std::string format_MAC(const unsigned char *buffer);

};

#endif // PACKET_PARSER_H
