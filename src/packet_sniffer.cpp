#include "packet_sniffer.h"

// Define the static member
PacketSniffer* PacketSniffer::global_packet_sniffer_instance = nullptr;

PacketSniffer::PacketSniffer(const Arguments& args) : pcap_handle(nullptr), arguments(args){
    PacketSniffer::global_packet_sniffer_instance = this;
    signal(SIGINT, signal_handler);
}

void PacketSniffer::start_sniffing() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open sniffing session
    pcap_handle = pcap_open_live(arguments.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == nullptr) {
        std::cerr << "ERR: Could not open interface " << errbuf << std::endl;
        exit(1);
    }

    // Add filter for capturing packets based on the user provided arguments
    std::string filter = set_filter();
    std::cout << filter << std::endl;

    // Compiled filter program
    struct bpf_program fp{};
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
    pcap_close(pcap_handle);
}

// Static member function to serve as a callback for pcap_loop
void PacketSniffer::packet_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data) {
    // Cast the userData pointer back to PacketParser object
    auto parser = reinterpret_cast<PacketParser*>(user_data);

    // Call the print_packet member function of PacketParser
    parser->print_packet(user_data, pkthdr, packet_data);
}

std::string PacketSniffer::set_filter() const {
    std::ostringstream filter;

    // Vector to store filter conditions
    std::vector<std::string> filter_conditions;

    // Add protocol filters
    if (arguments.tcp || arguments.udp || arguments.icmp4 || arguments.icmp6 || arguments.arp || arguments.ndp || arguments.igmp || arguments.mld) {
        std::ostringstream protocol_filter;
        protocol_filter << "(";
        bool added = false;
        if (arguments.tcp) {
            if(arguments.port_source != -1 || arguments.port_destination != -1){
                protocol_filter << "(tcp)" << " and " << set_port_filter();
            }
            else {
                protocol_filter << "tcp";
            }
            added = true;
        }
        if (arguments.udp) {
            if (added) protocol_filter << ") or (";
            if(arguments.port_source != -1 || arguments.port_destination != -1){
                protocol_filter << "(udp)" << " and " << set_port_filter();
            }
            else {
                protocol_filter << "udp";
            }

            added = true;
        }
        if (arguments.icmp4) {
            if (added) protocol_filter << ") or (";
            protocol_filter << "icmp";
            added = true;
        }
        if (arguments.icmp6) {
            if (added) protocol_filter << ") or (";
            // add filter for displaying only ICMPv6 request/response
            protocol_filter << "(icmp6 and ((icmp6[0] == 128 and icmp6[1] == 0) or (icmp6[0] == 129 and icmp6[1] == 0)))";
            added = true;
        }
        if (arguments.arp) {
            if (added) protocol_filter << ") or (";
            protocol_filter << "arp";
            added = true;
        }
        if (arguments.ndp) {
            if (added) protocol_filter << ") or (";
            // router solicitation/router advertisment/neighbor solicitation/neighbor advertisment/redirect message
            protocol_filter << "icmp6 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137)";
            added = true;
        }
        if (arguments.igmp) {
            if (added) protocol_filter << ") or (";
            protocol_filter << "igmp";
            added = true;
        }
        if (arguments.mld) {
            if (added) protocol_filter << ") or (";
            // query/report/done/discovery
            protocol_filter << "icmp6 and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132 or icmp6[0] == 143)";
            added = true;
        }
        protocol_filter << ")";
        filter_conditions.push_back(protocol_filter.str());
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

std::string PacketSniffer::set_port_filter() const {
    std::ostringstream port_filter;

    // Add port filters if specified
    if (arguments.port_destination != -1 || arguments.port_source != -1) {
        bool dst_port_added = false;

        if (arguments.port_destination != -1) {
            port_filter << "(dst port " << arguments.port_destination;
            dst_port_added = true;
            if(arguments.port_source != -1){
                port_filter << " or ";
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
    }

    return port_filter.str();
}

/**
 * @brief Function to terminate program after using CTRL+C
 *
 * @param signum
 */
void PacketSniffer::signal_handler(int signum) {
    if (PacketSniffer::global_packet_sniffer_instance != nullptr) {
        pcap_t* pcap_handle = PacketSniffer::global_packet_sniffer_instance->get_pcap_handle();

        // Get statistics from pcap handle
        pcap_stat stats{};
        if (pcap_stats(pcap_handle, &stats) == 0) {
            std::cout << std::endl;
            std::cout << "Packets received:       " << stats.ps_recv << std::endl;
            std::cout << "Packets dropped:        " << stats.ps_drop << std::endl;
            std::cout << "Packets dropped by NIC: " << stats.ps_ifdrop << std::endl;
        }

        // Close the pcap handle before exiting
        pcap_close(pcap_handle);
    }

    exit(0);
}

/**
 * @brief Getter function to access pcap_handle
 *
 * @return
 */
pcap_t* PacketSniffer::get_pcap_handle() const {
    return pcap_handle;
}
