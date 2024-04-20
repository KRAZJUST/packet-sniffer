# Network Sniffer Documentation
This documentation describes an implementation of the network analyzer that is capturing and filtering packets on a specific network interface - `Network Sniffer`. The `Network Sniffer` is implemented in `C++` making strong use of `PCAP (Packet Capture)` library. 

## Table of Contents
- [Network Sniffer Documentation](#network-sniffer-documentation)
  - [Table of Contents](#table-of-contents)
  - [Theory](#theory)
  - [Usage](#usage)

## Theory
This section will briefly describe the theory necessary for full understanding how does the `Network Sniffer` work.

**Network Sniffing**
Network sniffing is the process of intercepting and logging network traffic passing through a network interface. By capturing packets, network sniffers enable analysis of network activity. Captured packets can be analyzed to extract information such as source and destination addresses, protocol types, payload contents, etc.

**PCAP library**
`Packet Capture` library is broadly used framework for capturing, filtering  and analyzing network packets. It provides a platform-independent interface for accessing network data at the packet level. 
> Visit [tcpdump.org](https://www.tcpdump.org/) for more information.

**Protocols and Headers**
Network packets are structured according to various protocols, each with its own header format. Common protocols include `TCP`, `UDP`, `ICMP` and `ARP`, each with specific header fields defining packet attributes. While interpreting packet data, the most crucial part is understanding protocol headers.

## Usage
**Usage** of the Network Sniffer is:
```./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}```,
where supported command line arguments can be in any order and are described as follows:

| Option                  | Description                                                                                                                  |
|-------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `-i eth0`               | Specifies the network interface to sniff.                                                                                    |
| `--interface eth0`      | Specifies the network interface to sniff.                                                                                    |
| `-t`, `--tcp`           | Displays TCP segments.                                                                                                       |
| `-u`, `--udp`           | Displays UDP datagrams.                                                                                                      |
| `-p`                    | Extends previous two parameters to filter TCP/UDP based on port number.                                                      |
| `--port-destination 23` | Extends previous two parameters to filter TCP/UDP based on destination port number.                                          |
| `--port-source 23`      | Extends previous two parameters to filter TCP/UDP based on source port number.                                               |
| `--icmp4`               | Displays only ICMPv4 packets.                                                                                                |
| `--icmp6`               | Displays only ICMPv6 echo request/response.                                                                                  |
| `--arp`                 | Displays only ARP frames.                                                                                                    |
| `--ndp`                 | Displays only NDP packets, subset of ICMPv6.                                                                                 |
| `--igmp`                | Displays only IGMP packets.                                                                                                  |
| `--mld`                 | Displays only MLD packets, subset of ICMPv6.                                                                                 |
| `-n 10`                 | Specifies the number of packets to display. If not specified, only one packet is displayed.                                  |
