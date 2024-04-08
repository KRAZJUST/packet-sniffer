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
    if (pcap_loop(pcap_handle, arguments.packets_num, &PacketSniffer::packet_callback, nullptr) < 0) {
        std::cerr << "ERR: pcap_loop failed." << std::endl;
    }
    std::cout << "captured package" << std::endl;
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
    if (arguments.port_destination != -1 || arguments.port_source != -1) {
        std::ostringstream port_filter;
        bool dst_port_added = false;

        if (arguments.port_destination != -1) {
            port_filter << "(dst port " << arguments.port_destination;
            dst_port_added = true;
            if(arguments.port_source != -1){
                port_filter << "or ";
            }
        }
        if (arguments.port_source != -1) {
            if(dst_port_added){
                port_filter << "src port " << arguments.port_source;
            }
            else {
                port_filter << "(src port " << arguments.port_source;
            }
        }

        port_filter << ")";
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
