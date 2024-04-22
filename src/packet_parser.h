/**
 * @file packet_parser.h
 * @author David Skalka (xskalk03@stud.fit.vutbr.cz)
 * 
 * @brief Header file for packet_parser.cpp
 * 
 * @version 0.1
 * @date 2024-04-22
 * 
 * @copyright Copyright (c) 2024
 * 
 */

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

/**
 * @brief Class responsible for parsing and printing packet information.
 */
class PacketParser {
public:
    /**
     * @brief Construct a new Packet Parser object
     * 
     */
    PacketParser();


    /**
     * @brief Function to print packet information.
     * 
     * @param user_data User data passed to the callback function.
     * @param pkthdr Packet header information.
     * @param packet_data Packet data.
     */
    void print_packet(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data);


    /**
     * @brief Function to print IPv4 packet information.
     * 
     * @param ip_packet_data Pointer to the start of the IPv4 packet data.
     */
    static void print_ipv4_info(const u_char* ip_packet_data);


    /**
     * @brief Function to print IPv6 packet information.
     * 
     * @param ip_packet_data Pointer to the start of the IPv6 packet data.
     */
    void print_ipv6_info(const u_char* ip_packet_data);


    /**
     * @brief Function to print ARP packet information.
     * 
     * @param ip_packet_data Pointer to the start of the ARP packet data.
     * @param pkthdr Packet header information.
     */
    static void print_arp_info(const u_char* ip_packet_data, const struct pcap_pkthdr* pkthdr);


    /**
     * @brief Function to print the packet timestamp in RFC 3339 format.
     * 
     * @param pkthdr Packet header information.
     */
    static void print_timestamp(const struct pcap_pkthdr* pkthdr);


    /**
     * @brief Function to convert protocol number to a string representation.
     * 
     * @param protocol Protocol number.
     * @return String representation of the protocol.
     */
    static const char* protocol_to_string(uint8_t protocol);


    /**
     * @brief Function to print byte offset along with hexadecimal and ASCII representation.
     * 
     * @param data Packet data.
     * @param length Length of the packet data.
     */
    static void print_byte_offset(const u_char* data, unsigned int length);


    /**
     * @brief Function to format IPv6 address according to RFC5952 specifications.
     * 
     * @param ipv6_address IPv6 address to format.
     * @return Formatted IPv6 address.
     */
    std::string format_ipv6_address(const std::string& ipv6_address);


    /**
     * @brief Function to print ICMPv4 packet information.
     * 
     * @param icmp_packet_data Pointer to the start of the ICMPv4 packet data.
     */
    static void print_icmpv4_info(const u_char* icmp_packet_data);


    /**
     * @brief Function to print ICMPv6 packet information.
     * 
     * @param icmpv6_packet_data Pointer to the start of the ICMPv6 packet data.
     */
    static void print_icmpv6_info(const u_char* icmpv6_packet_data);


    /**
     * @brief Function to format MAC address.
     * 
     * @param buffer Buffer containing the MAC address.
     * @return Formatted MAC address.
     */
    std::string format_MAC(const unsigned char *buffer);

};

#endif // PACKET_PARSER_H
