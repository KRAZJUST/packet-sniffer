#include "arguments.h"


Arguments::Arguments(int argc, char* argv[]) {
    parse_cmd_arguments(argc, argv);
}

void Arguments::parse_cmd_arguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            interface = argv[++i];
        } else if ((arg == "-t" || arg == "--tcp")) {
            tcp = true;
        } else if ((arg == "-u" || arg == "--udp")) {
            udp = true;
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
        }
    }

    if(interface.empty()){
        print_interfaces();
        std::cout << "For more information run " << argv[0] << " -h" << std::endl;
        exit(0);
    }

    print_arguments();
}

void Arguments::print_help() {
    std::cout << "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n"
              << "Options:\n"
              << "  -i, --interface interface   Specify network interface to sniff\n"
              << "  -t, --tcp                   Display TCP segments\n"
              << "  -u, --udp                   Display UDP datagrams\n"
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

void Arguments::print_arguments(){

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

void Arguments::print_interfaces(){
    std::cout << "No interface specified, use one of the following active interfaces:" << std::endl;
    system("ip addr | grep 'state UP' -A2 | grep '^[0-9]' | awk '{print $2}' | cut -f1 -d'/'");
}