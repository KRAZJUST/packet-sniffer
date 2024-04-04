#include "packet_sniffer.h"

PacketSniffer::PacketSniffer(const Arguments& args) : arguments(args) {}


void PacketSniffer::start_sniffing() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = nullptr;

    // Check if the interface was specified
    if (!arguments.interface.empty()){
        dev = arguments.interface.c_str();
    }
    // If not interface was specified, try to find default devide
    else {
        if ((dev = pcap_lookupdev(errbuf)) == nullptr){
            std::cerr << "ERR: Could not find default device." << errbuf << std::endl;
            return;
        }
    }
    
    // Open sniffing session
    pcap_t* pcap_handle = pcap_open_live(arguments.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == nullptr) {
        std::cerr << "ERR: Could not open interface " << errbuf << std::endl;
        return;
    }

    // Apply filter to capture only IPv4 or IPv6 packets
    std::string filter = set_filter();
    std::cout << filter << std::endl;

    struct bpf_program fp;  // Compiled filter program
    if (pcap_compile(pcap_handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "ERR: Couldn't parse filter " << pcap_geterr(pcap_handle) << std::endl;
        pcap_close(pcap_handle);
        return;
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr << "ERR: Couldn't install filter " << pcap_geterr(pcap_handle) << std::endl;
        pcap_close(pcap_handle);
        return;
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

    // Add protocol filters
    if (arguments.tcp)
        filter_conditions.push_back("tcp");
    if (arguments.udp)
        filter_conditions.push_back("udp");
    if (arguments.icmp4)
        filter_conditions.push_back("icmp4");
    if (arguments.icmp6)
        filter_conditions.push_back("icmp6");
    if (arguments.arp)
        filter_conditions.push_back("arp");
    if (arguments.ndp)
        filter_conditions.push_back("ndp");
    if (arguments.igmp)
        filter_conditions.push_back("igmp");
    if (arguments.mld)
        filter_conditions.push_back("mld");

    // Add port filters if specified
    if (arguments.port_destination != 23 || (arguments.port_source != 0 && arguments.port_source != arguments.port_destination)) {
        std::ostringstream port_filter;
        port_filter << "port " << arguments.port_destination;
        if (arguments.port_source != 0 && arguments.port_source != arguments.port_destination) {
            port_filter << " or port " << arguments.port_source;
        }
        filter_conditions.push_back(port_filter.str());
    }

    // Concatenate filter conditions with "or"
    for (size_t i = 0; i < filter_conditions.size(); ++i) {
        filter << filter_conditions[i];
        if (i != filter_conditions.size() - 1)
            filter << " or ";
    }

    return filter.str();
}
