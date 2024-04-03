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
