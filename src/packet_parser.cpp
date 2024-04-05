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
    std::string protocol = protocol_to_string(ip_header->ip_p);
    std::cout << "protocol: " << protocol << std::endl;

    // Check if the protocol is UDP or TCP and print dst and src port based on it
    if (protocol == "UDP") {
        const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(ip_packet_data + sizeof(struct ip));
        std::cout << "src port: " << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "dst port: " << ntohs(udp_header->uh_dport) << std::endl;
    } else if (protocol == "TCP") {
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(ip_packet_data + sizeof(struct ip));
        std::cout << "src port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "dst port: " << ntohs(tcp_header->th_dport) << std::endl;
    }

    // Print identification number
    std::cout << "identification: " << ntohs(ip_header->ip_id) << std::endl;

    // Subtracting IP header length
    int payload_length = ntohs(ip_header->ip_len) - ip_header->ip_hl * 4;
    // Print byte offset
    print_byte_offset(ip_packet_data + ip_header->ip_hl * 4, payload_length);
}

void PacketParser::print_ipv6_info(const u_char* ip_packet_data) {
    // Extract IPv6 header
    const struct ip6_hdr* ipv6_header = reinterpret_cast<const struct ip6_hdr*>(ip_packet_data);

    // Print source and destination IPv6 addresses
    char source_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), source_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dest_ip, INET6_ADDRSTRLEN);
    std::cout << "src IP: " << source_ip << std::endl;
    std::cout << "dst IP: " << dest_ip << std::endl;

    // Print protocol type
    std::cout << "protocol: " << protocol_to_string(ipv6_header->ip6_nxt) << std::endl;

    // Print payload length of the IPv6 packet
    std::cout << "payload length: " << ntohs(ipv6_header->ip6_plen) << " bytes" << std::endl;
}

void PacketParser::print_arp_info(const u_char* arp_packet_data) {
    // Extract ARP header
    const struct ether_arp* arp_header = reinterpret_cast<const struct ether_arp*>(arp_packet_data);

    // Print source and destination MAC addresses
    std::cout << "src MAC: " << ether_ntoa((const struct ether_addr*)&arp_header->arp_sha) << std::endl;
    std::cout << "dst MAC: " << ether_ntoa((const struct ether_addr*)&arp_header->arp_tha) << std::endl;

    // Print source and destination IP addresses
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->arp_spa, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, dest_ip, INET_ADDRSTRLEN);
    std::cout << "src IP: " << source_ip << std::endl;
    std::cout << "dst IP: " << dest_ip << std::endl;

    std::cout << std::endl;
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

/**
 * @brief Print byte offset along with hexadecimal and ASCII representation
 *
 * @param data
 * @param length
 */
void PacketParser::print_byte_offset(const u_char* data, int length) {
    for (int i = 0; i < length; ++i) {
        if (i % 16 == 0) {
            // Print byte offset in hexadecimal format
            std::cout << std::setw(8) << std::setfill('0') << std::hex << i << ": ";
        }
        // Print each byte in hexadecimal format
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]) << " ";

        // Print ASCII representation
        if (i % 16 == 15 || i == length - 1) {
            // Calculate padding needed for the last line to align with previous lines
            int padding = 16 - (i % 16 + 1);
            // Fill remaining columns with spaces
            for (int p = 0; p < padding; ++p) {
                std::cout << "   ";
            }
            std::cout << "  ";
            // Print ASCII characters
            for (int j = i - (i % 16); j <= i; ++j) {
                // If the byte is printable, print the ASCII character, else print a dot
                if (j >= length) {
                    std::cout << "   ";
                } else if (data[j] >= 32 && data[j] <= 126) {
                    std::cout << static_cast<char>(data[j]);
                } else {
                    std::cout << ".";
                }
            }
            std::cout << std::endl;
        }
    }
}

