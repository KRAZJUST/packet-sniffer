/**
 * @file arguments.h
 * @author David Skalka (xskalk03@stud.fit.vutbr.cz)
 * 
 * @brief Header file for arguments.cpp
 * 
 * @version 0.1
 * @date 2024-04-22
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <string>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <vector>
#include <pcap.h>

/**
 * @brief The Arguments class handles parsing of command-line arguments for the ipk-sniffer program.
 *        It provides methods to parse command-line arguments, print help messages, print parsed arguments
 *        for debugging purposes, and print the available network interfaces.
 */
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

    /**
     * @brief Construct for Arguments class
     * 
     * @param argc 
     * @param argv 
     */
    Arguments(int argc, char* argv[]);


    /**
     * @brief Parses command-line arguments
     * 
     * @param argc 
     * @param argv 
     */
    void parse_cmd_arguments(int argc, char* argv[]);


    /**
     * @brief Prints the help message, describing the usage and available options of the ipk-sniffer program.
     * 
     */
    static void print_help();


    /**
     * @brief Prints the parsed command-line arguments for debugging purposes.
     * 
     */
    void print_arguments() const;


    /**
     * @brief Prints the available network interfaces to stdout.
     * 
     */
    static void print_interfaces();
};

#endif // ARGUMENTS_H
