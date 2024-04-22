/**
 * @file arguments.cpp
 * @author David Skalka (xskalk03@stud.fit.vutbr.cz)
 * 
 * @brief File implementing command-line argument parsing
 * 
 * @version 0.1
 * @date 2024-04-22
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "arguments.h"

/**
 * @brief Construct a new Arguments:: Arguments object
 * 
 * @param argc 
 * @param argv 
 */
Arguments::Arguments(int argc, char* argv[]) {
    parse_cmd_arguments(argc, argv);
}

/**
 * @brief Function for parsing command-line arguments
 * 
 * @param argc 
 * @param argv 
 */
void Arguments::parse_cmd_arguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--interface") {
            if(i + 1 < argc) {
                interface = argv[++i];
            } else {
                print_interfaces();
                exit(0);
            }
        } else if ((arg == "-t" || arg == "--tcp")) {
            tcp = true;
        } else if ((arg == "-u" || arg == "--udp")) {
            udp = true;
        } else if (arg == "-p" && i + 1 < argc) {
            int port = std::stoi(argv[++i]);
            port_source = port;
            port_destination = port;
        } else if (arg == "--port-destination" && i + 1 < argc) {
            port_destination = std::stoi(argv[++i]);
        } else if (arg == "--port-source" && i + 1 < argc) {
            port_source = std::stoi(argv[++i]);
        } else if (arg == "--icmp4") {
            icmp4 = true;
        } else if (arg == "--icmp6") {
            icmp6 = true;
        } else if (arg == "--arp") {
            arp = true;
        } else if (arg == "--ndp") {
            ndp = true;
        } else if (arg == "--igmp") {
            igmp = true;
        } else if (arg == "--mld") {
            mld = true;
        } else if (arg == "-n" && i + 1 < argc) {
            packets_num = std::stoi(argv[++i]);
        } else if (arg == "-h" || arg == "--help") {
            print_help();
            exit(0);
        } else {
            std::cout << "Unknown argument. For more information run " << argv[0] << " -h / --help." << std::endl;
            exit(0);
        }
    }

    if(interface.empty()){
        print_interfaces();
        std::cout << "For more information run " << argv[0] << " -h / --help." << std::endl;
        exit(0);
    }

    //print_arguments();
}

/**
 * @brief Function to print help
 * 
 */
void Arguments::print_help() {
    std::cout << "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n"
              << "Options:\n"
              << "  -i, --interface interface   Specify network interface to sniff\n"
              << "  -t, --tcp                   Display TCP segments\n"
              << "  -u, --udp                   Display UDP datagrams\n"
              << "  -p port                     Filter TCP/UDP based on the destination OR source port number\n"
              << "  --port-destination port     Filter TCP/UDP based on destination port number\n"
              << "  --port-source port          Filter TCP/UDP based on source port number\n"
              << "  --icmp4                     Display only ICMPv4 packets\n"
              << "  --icmp6                     Display only ICMPv6 echo request/response\n"
              << "  --arp                       Display only ARP frames\n"
              << "  --ndp                       Display only NDP packets (subset of ICMPv6)\n"
              << "  --igmp                      Display only IGMP packets\n"
              << "  --mld                       Display only MLD packets (subset of ICMPv6)\n"
              << "  -n num                      Number of packets to display (default: 1)\n"
              << "  -h, --help                  Display this help message\n";
}

/**
 * @brief Helper function fo debuging
 * 
 */
void Arguments::print_arguments() const{
    // Debug prints for checking the correct parsing of arguments
    std::cout << "interface: " << interface << std::endl;
    std::cout << "tcp: " << tcp << std::endl;
    std::cout << "udp: " << udp << std::endl;
    std::cout << "port_destination: " << port_destination << std::endl;
    std::cout << "port_source: " << port_source << std::endl;
    std::cout << "icmp4: " << icmp4 << std::endl;
    std::cout << "icmp6: " << icmp6 << std::endl;
    std::cout << "arp: " << arp << std::endl;
    std::cout << "ndp: " << ndp << std::endl;
    std::cout << "igmp: " << igmp << std::endl;
    std::cout << "mld: " << mld << std::endl;
    std::cout << "packets_num: " << packets_num << std::endl;
}

/**
 * @brief Function to print active interfaces
 * 
 */
void Arguments::print_interfaces() {
    std::cout << "No interface specified, use one of the following active interfaces:" << std::endl;

    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the list of all network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return;
    }

    // Iterate through the list of interfaces and print the names of active ones
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        if (d->flags & PCAP_IF_UP && d->flags & PCAP_IF_RUNNING) {
            std::cout << d->name << std::endl;
        }
    }

    // Free the list of interfaces
    pcap_freealldevs(alldevs);
}