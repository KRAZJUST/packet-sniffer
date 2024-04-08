#include "packet_sniffer.h"

PacketSniffer::PacketSniffer(const Arguments& args) : arguments(args) {}


void PacketSniffer::start_sniffing() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open sniffing session
    pcap_t* pcap_handle = pcap_open_live(arguments.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == nullptr) {
        std::cerr << "ERR: Could not open interface " << errbuf << std::endl;
        exit(1);
    }

    // Apply filter to capture only IPv4 or IPv6 packets
    std::string filter = set_filter();
    std::cout << filter << std::endl;

    struct bpf_program fp;  // Compiled filter program
    if (pcap_compile(pcap_handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "ERR: Couldn't parse filter " << pcap_geterr(pcap_handle) << std::endl;
        pcap_close(pcap_handle);
        exit(1);
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr << "ERR: Couldn't install filter " << pcap_geterr(pcap_handle) << std::endl;
        pcap_close(pcap_handle);
        exit(1);
    }

    // Catch packets_num number of packets
    pcap_loop(pcap_handle, arguments.packets_num, &PacketSniffer::packet_callback, nullptr);
    pcap_close(pcap_handle);
}

// Static member function to serve as a callback for pcap_loop
void PacketSniffer::packet_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data) {
    // Cast the userData pointer back to PacketParser object
    PacketParser* parser = reinterpret_cast<PacketParser*>(user_data);

    // Call the print_packet member function of PacketParser
    parser->print_packet(user_data, pkthdr, packet_data);
}

std::string PacketSniffer::set_filter() {
    std::ostringstream filter;

    // Vector to store filter conditions
    std::vector<std::string> filter_conditions;

    // Add interface filter if specified
    if (!arguments.interface.empty()) {
        std::string interface_ip = get_interface_ip(arguments.interface);
        if (!interface_ip.empty()) {
            filter_conditions.push_back("src or dst host " + interface_ip);
        } else {
            std::cerr << "ERR: Interface IP not found for " << arguments.interface << std::endl;
            exit(1);
        }
    }

    // Add protocol filters
    if (arguments.tcp || arguments.udp || arguments.icmp4 || arguments.icmp6 || arguments.arp || arguments.ndp || arguments.igmp || arguments.mld) {
        std::ostringstream protocol_filter;
        protocol_filter << "(";
        bool added = false;
        if (arguments.tcp) {
            protocol_filter << "tcp";
            added = true;
        }
        if (arguments.udp) {
            if (added) protocol_filter << " or ";
            protocol_filter << "udp";
            added = true;
        }
        if (arguments.icmp4) {
            if (added) protocol_filter << " or ";
            protocol_filter << "icmp";
            added = true;
        }
        if (arguments.icmp6) {
            if (added) protocol_filter << " or ";
            protocol_filter << "icmp6";
            added = true;
        }
        if (arguments.arp) {
            if (added) protocol_filter << " or ";
            protocol_filter << "arp";
            added = true;
        }
        if (arguments.ndp) {
            if (added) protocol_filter << " or ";
            protocol_filter << "ndp";
            added = true;
        }
        if (arguments.igmp) {
            if (added) protocol_filter << " or ";
            protocol_filter << "igmp";
            added = true;
        }
        if (arguments.mld) {
            if (added) protocol_filter << " or ";
            protocol_filter << "mld";
            added = true;
        }
        protocol_filter << ")";
        filter_conditions.push_back(protocol_filter.str());
    }

    // Add port filters if specified
    if (arguments.port_destination != -1 || (arguments.port_source != -1 && arguments.port_source != arguments.port_destination)) {
        std::ostringstream port_filter;
        if (arguments.port_destination != -1) {
            port_filter << "port " << arguments.port_destination;
        } else {
            port_filter << "portrange 1-65535"; // Sniff on any port
        }
        if (arguments.port_source != -1 && arguments.port_source != arguments.port_destination) {
            port_filter << " or port " << arguments.port_source;
        }
        filter_conditions.push_back(port_filter.str());
    }


    // Concatenate filter conditions with "and"
    for (size_t i = 0; i < filter_conditions.size(); ++i) {
        if (i != 0) {
            filter << " and ";
        }
        filter << filter_conditions[i];
    }

    return filter.str();
}

std::string PacketSniffer::get_interface_ip(const std::string& interface) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    if (getifaddrs(&ifap) == -1) {
        std::cerr << "ERR: Couldn't get the interface address." << std::endl;
        exit(EXIT_FAILURE);
    }

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            if (std::string(ifa->ifa_name) == interface) {
                freeifaddrs(ifap);
                return std::string(addr);
            }
        }
    }

    freeifaddrs(ifap);
    return "";
}
