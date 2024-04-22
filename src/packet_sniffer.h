/**
 * @file packet_sniffer.h
 * @author David Skalka (xskalk03@stud.fit.vutbr.cz)
 * 
 * @brief Header file for packet_sniffer.cpp
 * 
 * @version 0.1
 * @date 2024-04-22
 * 
 * @copyright Copyright (c) 2024
 * 
 */

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

// Define a flag to indicate if a SIGINT signal has been received
extern std::atomic<bool> sigint_received;

/**
 * @brief Class responsible for packet sniffing functionality.
 */
class PacketSniffer {
public:

    /**
     * @brief Constructor for the PacketSniffer class.
     * 
     * @param args The Arguments object containing parsed command-line arguments.
     */
    PacketSniffer(const Arguments& args);


    /**
     * @brief Destructor for the PacketSniffer class.
     * 
     * Closes the pcap handle if it's not nullptr.
     */
    ~PacketSniffer();


    /**
     * @brief Static member function to serve as a callback for pcap_loop.
     * 
     * @param user_data User data passed to the callback function.
     * @param pkthdr Packet header information.
     * @param packet_data Packet data.
     */
    static void packet_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data);


    /**
     * @brief Starts the packet sniffing process.
     * 
     * Opens a live sniffing session, sets the filter based on user provided arguments,
     * and starts capturing packets.
     */
    void start_sniffing();


    /**
     * @brief Sets the packet filter based on user-provided arguments.
     * 
     * @return The string representation of the filter.
     */
    std::string set_filter() const;


    /**
     * @brief Sets the port filter based on user-provided arguments.
     * 
     * @return The string representation of the port filter.
     */
    std::string set_port_filter() const;

private:
    // Pointer to te pcap handle
    pcap_t* pcap_handle;
    // Instance of Arguments containing parsed command-line arguments
    Arguments arguments;
    // Static pointer to hold the PacketSniffer instance
    static PacketSniffer* global_packet_sniffer_instance;


    /**
     * @brief Getter function to access the pcap handle.
     * 
     * @return The pcap handle.
     */
    pcap_t* get_pcap_handle() const;


    /**
     * @brief Static function to handle SIGINT signal.
     * 
     * @param signum Signal number.
     */
    static void signal_handler(int signum);
};

#endif // PACKET_SNIFFER_H