#include "packet_parser.h"

PacketParser::PacketParser() {}

void PacketParser::print_packet(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data) {

    // Print timestamp in RFC 3339 format
    print_timestamp(pkthdr);

    // Extract and print Ethernet header
    struct ether_header* eth_header = (struct ether_header*)packet_data;

    // Print source and destination MAC addresses
    std::cout << "src MAC: " << ether_ntoa((const struct ether_addr*)&eth_header->ether_shost) << std::endl;
    std::cout << "dst MAC: " << ether_ntoa((const struct ether_addr*)&eth_header->ether_dhost) << std::endl;

    // Extract and print frame length
    std::cout << "frame length: " << pkthdr->len << " bytes" << std::endl;

    // Determine the type of the next protocol
    uint16_t ether_type = ntohs(eth_header->ether_type);

    // Delegate further printing based on the next protocol type
    // IPv4
    if (ether_type == ETHERTYPE_IP) {
        print_ipv4_info(packet_data + sizeof(struct ether_header));
    // IPv6
    } else if (ether_type == ETHERTYPE_IPV6) {
        print_ipv6_info(packet_data + sizeof(struct ether_header));
    // ARP
    } else if (ether_type == ETHERTYPE_ARP) {
        print_arp_info(packet_data + sizeof(struct ether_header));
    } else {
        // Unsupported protocol type
        std::cout << "Unsupported protocol type" << std::endl;
    }
}

const char* PacketParser::protocol_to_string(uint8_t protocol) {
    switch(protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        default:
            return "Unknown";
    }
}

void PacketParser::print_ipv4_info(const u_char* ip_packet_data) {

    // Extract IPv4 header
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(ip_packet_data);

    // Print source and destination IP addresses
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    std::cout << "src IP: " << source_ip << std::endl;
    std::cout << "dst IP: " << dest_ip << std::endl;

    // Print protocol type
    std::cout << "protocol: " << protocol_to_string(ip_header->ip_p) << std::endl;

    // Print total length of the IPv4 packet
    std::cout << "total length: " << ntohs(ip_header->ip_len) << " bytes" << std::endl;

    // Print identification number
    std::cout << "identification: " << ntohs(ip_header->ip_id) << std::endl;

    // Print Time To Live (TTL) value
    std::cout << "TTL: " << static_cast<int>(ip_header->ip_ttl) << std::endl;
}

void PacketParser::print_ipv6_info(const u_char* ip_packet_data) {
    //TODO
}

void PacketParser::print_arp_info(const u_char* arp_packet_data) {
    //TODO
}

void PacketParser::print_timestamp(const struct pcap_pkthdr* pkthdr){
    
    // Extract timestamp
    time_t rawtime = pkthdr->ts.tv_sec;
    struct tm* timeinfo;
    char timestamp[80];
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", timeinfo);
    
    // Print timestamp in RFC 3339 format
    std::cout << "timestamp: " << timestamp << std::endl;
}