#include "packet_parser.h"

PacketParser::PacketParser() {}

void PacketParser::print_packet(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data) {

    // Print timestamp in RFC 3339 format
    print_timestamp(pkthdr);

    // Extract and print Ethernet header
    auto* eth_header = (struct ether_header*)packet_data;

    // Print source and destination MAC addresses
    std::cout << "src MAC: " << format_MAC(eth_header->ether_shost) << std::endl;
    std::cout << "dst MAC: " << format_MAC(eth_header->ether_dhost) << std::endl;

    // Extract and print frame length
    std::cout << "frame length: " << std::dec << pkthdr->len << " bytes" << std::endl;

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
        std::cout << "protocol: ARP" << std::endl;
        print_arp_info(packet_data + sizeof(struct ether_header), pkthdr);
    } else {
        // Unsupported protocol type
        std::cout << "Unsupported protocol type" << std::endl;
    }

    print_byte_offset(packet_data, pkthdr->len);
}

const char* PacketParser::protocol_to_string(uint8_t protocol, int ipv_num) {
    switch(protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            if(ipv_num == 4) {
                return "ICMPv4";
            }
            else if(ipv_num == 6){
                return "ICMPv6";
            }
            return "Unknown";
        case IPPROTO_IGMP:
            return "IGMP";
        default:
            return "Unknown";
    }
}

void PacketParser::print_ipv4_info(const u_char* ip_packet_data) {

    // Extract IPv4 header
    const auto* ip_header = reinterpret_cast<const struct ip*>(ip_packet_data);

    // Print source and destination IP addresses
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    std::cout << "src IP: " << source_ip << std::endl;
    std::cout << "dst IP: " << dest_ip << std::endl;

    // Print protocol type
    std::string protocol = protocol_to_string(ip_header->ip_p, 4);
    std::cout << "protocol: " << protocol << std::endl;
    

    // Print more specific information based on the protocol type
    if (protocol == "UDP") {
        const auto* udp_header = reinterpret_cast<const struct udphdr*>(ip_packet_data + sizeof(struct ip));
        std::cout << "src port: " << std::dec << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "dst port: " << std::dec << ntohs(udp_header->uh_dport) << std::endl;
    } else if (protocol == "TCP") {
        const auto* tcp_header = reinterpret_cast<const struct tcphdr*>(ip_packet_data + sizeof(struct ip));
        std::cout << "src port: " << std::dec << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "dst port: " << std::dec << ntohs(tcp_header->th_dport) << std::endl;
    } else if (protocol == "ICMPv4"){
        print_icmpv4_info(ip_packet_data + sizeof(struct ip));
    } else if (protocol == "IGMP"){
        // Extract IGMP header
        const auto* igmp_header = reinterpret_cast<const struct igmp*>(ip_packet_data + sizeof(struct ip));
        // Determine IGMP version based on message type
        std::cout << std::dec << "IGMP version: " << igmp_header->igmp_type << std::endl;
    }

}

void PacketParser::print_ipv6_info(const u_char* ip_packet_data) {
    // Extract IPv6 header
    const auto* ipv6_header = reinterpret_cast<const struct ip6_hdr*>(ip_packet_data);

    // Print source and destination IPv6 addresses
    char source_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), source_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dest_ip, INET6_ADDRSTRLEN);

    // Convert IPv6 addresses to preferred form
    std::string formatted_source_ip = format_ipv6_address(source_ip);
    std::string formatted_dest_ip = format_ipv6_address(dest_ip);
    std::cout << "src IP: " << formatted_source_ip << std::endl;
    std::cout << "dst IP: " << formatted_dest_ip << std::endl;

    // Print protocol type
    std::string protocol = protocol_to_string(ipv6_header->ip6_nxt, 6);
    if(protocol != "ICMPv6"){
        std::cout << "protocol: " << protocol << std::endl;
    }

    // Print more specific information based on the protocol type
    if (protocol == "UDP") {
        const auto* udp_header = reinterpret_cast<const struct udphdr*>(ip_packet_data + sizeof(struct ip));
        std::cout << "src port: " << std::dec << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "dst port: " << std::dec << ntohs(udp_header->uh_dport) << std::endl;
    } else if (protocol == "TCP") {
        const auto* tcp_header = reinterpret_cast<const struct tcphdr*>(ip_packet_data + sizeof(struct ip));
        std::cout << "src port: " << std::dec << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "dst port: " << std::dec << ntohs(tcp_header->th_dport) << std::endl;
    } else if (protocol == "ICMPv6"){
        print_icmpv6_info(ip_packet_data + sizeof(struct ip6_hdr));
    }
}

void PacketParser::print_arp_info(const u_char* arp_packet_data, const struct pcap_pkthdr* pkthdr) {
    // Extract ARP header
    const auto* arp_header = reinterpret_cast<const struct ether_arp*>(arp_packet_data);

    // Print source and destination IP addresses
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->arp_spa, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, dest_ip, INET_ADDRSTRLEN);
    std::cout << "src IP: " << source_ip << std::endl;
    std::cout << "dst IP: " << dest_ip << std::endl;
}

/**
 * @brief Function to print package's timestamp in
 *
 * @param pkthdr
 */
void PacketParser::print_timestamp(const struct pcap_pkthdr* pkthdr){

    // Convert the packets timestamp to a time_t structure
    time_t timestamp = pkthdr->ts.tv_sec;
    struct tm* tm_info = localtime(&timestamp);

    // Format the timestamp according to RFC 3339 with milliseconds and timezone offset
    char buffer[50];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", tm_info);

    // Append milliseconds
    std::stringstream ss;
    ss << std::fixed << std::setfill('0') << std::setw(3) << (int)(pkthdr->ts.tv_usec / 1000);
    std::string milliseconds = ss.str();
    strcat(buffer, ".");
    strcat(buffer, milliseconds.c_str());

    // Append timezone offset
    char time_zone[7];
    strftime(time_zone, sizeof(time_zone), "%z", tm_info);
    strcat(buffer, time_zone);

    // Output the formatted timestamp
    std::cout << "timestamp: " << buffer << std::endl;
}

/**
 * @brief Print byte offset along with hexadecimal and ASCII representation
 *
 * @param data
 * @param length
 */
void PacketParser::print_byte_offset(const u_char* data, unsigned int length) {
    for (unsigned int i = 0; i < length; ++i) {
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
            for (unsigned int j = i - (i % 16); j <= i; ++j) {
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

/**
 * @brief Function to format IPv6 address according to RFC5952 specifications
 *
 * @param ipv6_address
 * @return
 */
std::string PacketParser::format_ipv6_address(const std::string& ipv6_address) {
    // Split the IPv6 address into its components
    std::istringstream iss(ipv6_address);
    std::string component;
    std::vector<std::string> components; // Declare components vector
    while (std::getline(iss, component, ':')) {
        components.push_back(component);
    }

    // Count the consecutive zeros in the address
    int consecutive_zeros = 0;
    int max_consecutive_zeros = 0;
    bool counting_zeros = false;
    for (const auto& comp : components) {
        if (comp.empty()) {
            if (counting_zeros) {
                consecutive_zeros++;
            } else {
                counting_zeros = true;
                consecutive_zeros = 1;
            }
        } else {
            counting_zeros = false;
            if (consecutive_zeros > max_consecutive_zeros) {
                max_consecutive_zeros = consecutive_zeros;
            }
        }
    }

    // Replace the longest consecutive zeros with "::"
    std::ostringstream formatted_address;
    for (size_t i = 0; i < components.size(); ++i) {
        if (components[i].empty()) {
            if (consecutive_zeros == max_consecutive_zeros) {
                if (i == 0 || i == components.size() - 1) {
                    formatted_address << "::";
                }
                consecutive_zeros--;
            }
        } else {
            formatted_address << components[i];
            if (i != components.size() - 1) {
                formatted_address << ":";
            }
        }
    }

    return formatted_address.str();
}

void PacketParser::print_icmpv4_info(const u_char* icmp_packet_data) {
    // Extract ICMP header
    const auto* icmp_header = reinterpret_cast<const struct icmp*>(icmp_packet_data);

    // Print ICMP type and code
    std::cout << "ICMPv4 type: " << static_cast<int>(icmp_header->icmp_type) << std::endl;
    std::cout << "ICMPv4 code: " << static_cast<int>(icmp_header->icmp_code) << std::endl;
}

void PacketParser::print_icmpv6_info(const u_char* icmpv6_packet_data) {
    // Extract ICMPv6 header
    const auto* icmpv6_header = reinterpret_cast<const struct icmp6_hdr*>(icmpv6_packet_data);
    
    if(icmpv6_header->icmp6_type == 130 || icmpv6_header->icmp6_type == 131 || icmpv6_header->icmp6_type == 132 || icmpv6_header->icmp6_type == 143){
        std::cout << "protocol: MLD" << std::endl;
    } else if (icmpv6_header->icmp6_type == 133 || icmpv6_header->icmp6_type == 134 || icmpv6_header->icmp6_type == 135 || icmpv6_header->icmp6_type == 136 ||
               icmpv6_header->icmp6_type == 137){
        std::cout << "protocol: NDP" << std::endl;
    } else{
        std::cout << "protocol: ICMPv6" << std::endl;
    }

    // Print ICMPv6 type and code
    std::cout << "ICMPv6 type: " << static_cast<int>(icmpv6_header->icmp6_type) << std::endl;
    std::cout << "ICMPv6 code: " << static_cast<int>(icmpv6_header->icmp6_code) << std::endl;
}


std::string PacketParser::format_MAC(const unsigned char *buffer) {
    std::stringstream output;

    output << std::hex << std::setfill('0');
    
    for (int i = 0; i < 6; i++) {
        output << std::setw(2) << static_cast<int>(buffer[i]);
        
        if (i != 5) {
            output << ":";
        }
    }
    return output.str();
}

