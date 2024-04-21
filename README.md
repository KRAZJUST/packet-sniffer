# Network Sniffer Documentation

This documentation describes an implementation of the network analyzer that is capturing and filtering packets on a specific network interface - `Network Sniffer`. The `Network Sniffer` is implemented in `C++` making strong use of `PCAP (Packet Capture)` library.

## Table of Contents

- [Network Sniffer Documentation](#network-sniffer-documentation)
  - [Table of Contents](#table-of-contents)
  - [Theory](#theory)
    - [Network Sniffing](#network-sniffing)
    - [PCAP library](#pcap-library)
    - [Protocols and Headers](#protocols-and-headers)
  - [Usage](#usage)
  - [Source code](#source-code)
    - [Arguments](#arguments)
    - [PacketSniffer](#packetsniffer)
    - [PacketParser](#packetparser)
    - [UML Class Diagram](#uml-class-diagram)
    - [Interaction flow](#interaction-flow)
  - [Testing](#testing)
    - [Testing enviroment](#testing-enviroment)
    - [Command-line argument](#command-line-argument)
    - [Setting up the filter](#setting-up-the-filter)

## Theory

This section will briefly describe the theory necessary for full understanding how does the `Network Sniffer` work.

### Network Sniffing

Network sniffing is the process of intercepting and logging network traffic passing through a network interface. By capturing packets, network sniffers enable analysis of network activity. Captured packets can be analyzed to extract information such as source and destination addresses, protocol types, payload contents, etc.

### PCAP library

`Packet Capture` library is broadly used framework for capturing, filtering  and analyzing network packets. It provides a platform-independent interface for accessing network data at the packet level.
> Visit [tcpdump.org](https://www.tcpdump.org/) for more information.

### Protocols and Headers

Network packets are structured according to various protocols, each with its own header format. Common protocols include `TCP`, `UDP`, `ICMP` and `ARP`, each with specific header fields defining packet attributes. While interpreting packet data, the most crucial part is understanding protocol headers.

## Usage

**Usage** of the Network Sniffer is:

```./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}```

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

## Source code

The source code contains three classes: `Arguments`, `PacketSniffer`, and `PacketParser`, that are designed to provide packet capturing and analysis. In the following section will be each class shortly described, for a deeper understanding of implemented methods, please refer to the source code files, where each method is thoroughly described.

### Arguments

- Responsible for parsing command-line arguments.
- Stores information about network interface, protocol preferences, packet filters, and packet count.
- Offers methods to print help information and available network interfaces.

### PacketSniffer

- Initializes and manages packet sniffing using libpcap.
- Provides a callback function `packet_callback` to process captured packets.
- Offers methods to start and stop packet sniffing.

### PacketParser

- Handles parsing and printing of packet information.
- Provides methods to print packet headers, timestamps, and byte offsets.
  
### UML Class Diagram

UML Class Diagram to display the communication between classes.
![UML Class Diagram](images/UMLPNG.png)

### Interaction flow

This is the simplified representation of the flow while running the `Network Sniffer`:

```text
Main
 |
 |   Arguments
 |     |
 |     | Parse command-line arguments
 |     v
 |   PacketSniffer
 |     |
 |     | Create PacketSniffer instance with parsed arguments
 |     v
 |     Start sniffing
 |       |
 |       | Packet capture callback
 |       v
 |     PacketParser
 |       |
 |       | Print captured packet information
 |       v
 |     PacketSniffer
 |       |
 |       | Continue sniffing / N packets captured - stop sniffing
 |       v
 ```

## Testing

In this section will be displayed the program outputs for specific tested scenarios. The testing of `Network Sniffer` was done with the usage of the program `Wireshark` where captured packets were compared to the data of the same packet captured by the `Wireshark`.

### Testing enviroment

The testing part was done in the terminal of the computer with following specification:

`Linux MiWiFi-R4CM-srv 6.7.10-200.fc39.x86_64 #1 SMP PREEMPT_DYNAMIC Mon Mar 18 18:56:52 UTC 2024 x86_64 GNU/Linux`

The used g++ compiler:

```text
g++ (GCC) 13.2.1 20240316 (Red Hat 13.2.1-7)
Copyright (C) 2023 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

The network interfaces and their configurations (IP and MAC addresses are not shown whole from security reasons):

```text
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:XX:XX brd 00:00:00:00:XX:XX
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 28:f1:0e:2d:XX:XX brd ff:ff:ff:ff:XX:XX
    inet 192.168.XX.XXX/XX brd 192.168.XX.XXX scope global dynamic noprefixroute enp0s31f6
       valid_lft 38708sec preferred_lft 38708sec
    inet6 fe80::14f1:97d6:c1fd:XXXX/XX scope link noprefixroute 
       valid_lft forever preferred_lft forever
3: wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether e4:a4:71:82:XX:XX brd ff:ff:ff:ff:XX:XX
    inet 192.168.XX.XX/XX brd 192.168.XX.XXX scope global dynamic noprefixroute wlp1s0
       valid_lft 38710sec preferred_lft 38710sec
    inet6 fe80::56db:2d6:7e21:XXXX/XX scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

### Command-line argument

The first thing to be tested is correct command-line argument parsing and setting corresponding flags for later filtering

**The following text snippets will contain an examples of console inputs/outputs while running the `Network Sniffer` with different command-line arguments.**

Test for the accurate setting of the flags for different arguments (print for each flag was added to see the correct functionality):

```text
sudo ./ipk-sniffer --interface lo --tcp --udp --icmp6 --port-source 23 --igmp --arp -n 13
interface: lo
tcp: 1
udp: 1
port_destination: -1
port_source: 23
icmp4: 0
icmp6: 1
arp: 1
ndp: 0
igmp: 1
mld: 0
packets_num: 13
```

Test for the usage of the `Network Sniffer` without specified interface:

```text
sudo ./ipk-sniffer --interface
No interface specified, use one of the following active interfaces:
wlp1s0
any
lo
```

Test for the usage of the `Network Sniffer` with unknown argument:

```text
sudo ./ipk-sniffer --interface --tcp --udp --protocol321
Unknown argument. For more information run ./ipk-sniffer -h / --help.
```

### Setting up the filter

Another part of the program to be thoroughly tested is setting up the `PCAP filter` from the command-line arguments to capture only necessary packets.

**The following text snippets will contain an examples of created `filter` while running the `Network Sniffer` with different command-line arguments.**

Test for the filter  with only basic arguments:

```text
sudo ./ipk-sniffer --interface wlp1s0 --tcp --udp
filter: (tcp) or (udp)
```

Test for the more complex filter with more arguments:

```text
sudo ./ipk-sniffer --interface wlp1s0 --tcp --udp --icmp4 --ndp --arp
filter: (tcp) or (udp) or (icmp) or (arp) or (icmp6 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137))
```

Test for the filter with specified port numbers (src port = 87 and dst port = 34):

```text
sudo ./ipk-sniffer --interface wlp1s0 --tcp --udp --port-destination 34 --port-source 87
filter: ((tcp) and (dst port 34 or src port 87)) or ((udp) and (dst port 34 or src port 87))
```
