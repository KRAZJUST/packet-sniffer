# Author: David Skalka

import subprocess
import time
from scapy.all import Ether, IP, TCP, UDP, ARP, ICMP, sendp, IPv6, ICMPv6EchoRequest
from scapy.layers.inet6 import _ICMPv6 as ICMPv6

def print_passed(message):
    """
    Print a message indicating a test passed in green.
    """
    print("\033[92m[PASSED]\033[0m", message)

def print_failed(message):
    """
    Print a message indicating a test failed in red.
    """
    print("\033[91m[FAILED]\033[0m", message)

def start_sniffer(interface, options):
    """
    Start the ipk-sniffer program in the background with the given interface and options.
    """
    command = ["sudo", "./ipk-sniffer", "--interface", interface] + options
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process

def stop_sniffer(process):
    """
    Stop the ipk-sniffer process.
    """
    process.terminate()
    process.wait()

def send_tcp_packet():
    """
    Send a TCP packet.
    """
    # Craft TCP packet
    tcp_packet = Ether() / IP(dst="192.168.0.39") / TCP(dport=34860, sport=443)
    packet_length_str = str(len(tcp_packet)) + " bytes"
    # Return the packet
    return tcp_packet, packet_length_str

def send_udp_packet():
    """"
    Send a UDP packet.
    """
    # Craft UDP packet
    udp_packet = Ether() / IP(dst="192.168.0.39") / UDP(dport=53, sport=12345)
    packet_length_str = str(len(udp_packet)) + " bytes"
    # Return the packet
    return udp_packet, packet_length_str

def send_arp_packet():
    """
    Send an ARP packet.
    """
    # Craft ARP packet
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.0.1", hwdst="ff:ff:ff:ff:ff:ff")
    packet_length_str = str(len(arp_packet)) + " bytes"
    # Return the packet
    return arp_packet, packet_length_str

def send_icmpv6_packet():
    """
    Send an ICMPv6 packet.
    """
    # Craft ICMPv6 packet
    icmpv6_packet = Ether() / IPv6(dst="fe80::1") / ICMPv6EchoRequest()
    packet_length_str = str(len(icmpv6_packet)) + " bytes"
    # Return the packet
    return icmpv6_packet, packet_length_str

def send_icmpv4_packet():
    """
    Send an ICMPv4 packet.
    """
    # Craft ICMPv4 packet
    icmpv4_packet = Ether() / IP(dst="192.168.0.1") / ICMP()
    packet_length_str = str(len(icmpv4_packet)) + " bytes"
    # Return the packet
    return icmpv4_packet, packet_length_str

def capture_output(process):
    """
    Capture output of ipk-sniffer process.
    """
    output, _ = process.communicate()
    return output.decode("utf-8")

def parse_captured_packet(output):
    """
    Parse captured packet from ipk-sniffer output.
    """
    packet_info = {}
    lines = output.strip().split("\n")

    # Skip the first line since it contains "(tcp)"
    lines = lines[1:]

    for line in lines:
        parts = line.split(":")
        if len(parts) == 2:
            if parts[0].strip() == '00000000':
                break
            key, value = parts[0].strip(), parts[1].strip()
            packet_info[key] = value
    #print(packet_info)
    return packet_info

def test_send_tcp_packet():
    """
    Test sending a TCP packet and capturing it with ipk-sniffer.
    """
    try:
        # Start the sniffer
        sniffer_process = start_sniffer("lo", ["--tcp", "-n", "1"])

        # Wait for the sniffer to initialize
        time.sleep(1)

        # Send TCP packet
        sent_packet, packet_len = send_tcp_packet()
        
        # Save sent packet information
        sent_packet_info = {
            #"src_mac": sent_packet[Ether].src,
            #"dst_mac": sent_packet[Ether].dst,
            "frame length": packet_len,
            "src IP": sent_packet[IP].src,
            "dst IP": sent_packet[IP].dst,
            "protocol": "TCP"
        }

        print("\033[94mSEND PACKET INFO:\033[0m", sent_packet_info)

        sendp(sent_packet, iface="lo")

        # Wait for packet to be captured
        time.sleep(1)

        # Capture output of ipk-sniffer
        sniffer_output = capture_output(sniffer_process)

        # Parse captured packet information
        captured_packet_info = parse_captured_packet(sniffer_output)
        print("\033[93mCAPTURED PACKET INFO:\033[0m", captured_packet_info)

        # Compare packet information
        for key, value in sent_packet_info.items():
            assert captured_packet_info.get(key) == value, f"{key} mismatch"

        print_passed("TCP packet test passed successfully")

    except Exception as e:
        print_failed("TCP packet test failed")
        print(e)

    finally:
        # Stop the sniffer
        stop_sniffer(sniffer_process)


def test_send_udp_packet():
    """
    Test sending a UDP packet and capturing it with ipk-sniffer.
    """
    try:
        # Start the sniffer
        sniffer_process = start_sniffer("lo", ["--udp", "-n", "1"])

        # Wait for the sniffer to initialize
        time.sleep(1)

        # Send UDP packet
        sent_packet, packet_len = send_udp_packet()
        
        # Save sent packet information
        sent_packet_info = {
            #"src_mac": sent_packet[Ether].src,
            #"dst_mac": sent_packet[Ether].dst,
            "frame length": packet_len,
            "src IP": sent_packet[IP].src,
            "dst IP": sent_packet[IP].dst,
            "protocol": "UDP"
        }
        print("\033[94mSEND PACKET INFO:\033[0m", sent_packet_info)

        sendp(sent_packet, iface="lo")

        # Wait for packet to be captured
        time.sleep(1)

        # Capture output of ipk-sniffer
        sniffer_output = capture_output(sniffer_process)

        # Parse captured packet information
        captured_packet_info = parse_captured_packet(sniffer_output)
        print("\033[93mCAPTURED PACKET INFO:\033[0m", captured_packet_info)

        # Compare packet information
        for key, value in sent_packet_info.items():
            assert captured_packet_info.get(key) == value, f"{key} mismatch"

        print_passed("UDP packet test passed successfully")

    except Exception as e:
        print_failed("UDP packet test failed")
        print(e)

    finally:
        # Stop the sniffer
        stop_sniffer(sniffer_process)


def test_send_arp_packet():
    """
    Test sending an ARP packet and capturing it with ipk-sniffer.
    """
    try:
        # Start the sniffer
        sniffer_process = start_sniffer("lo", ["--arp", "-n", "1"])

        # Wait for the sniffer to initialize
        time.sleep(1)

        # Send ARP packet
        sent_packet, packet_len = send_arp_packet()
        
        # Save sent packet information
        sent_packet_info = {
            #"src_mac": sent_packet[Ether].src,
            #"dst_mac": sent_packet[Ether].dst,
            "frame length": packet_len,
            "src IP": sent_packet[ARP].psrc,
            "dst IP": sent_packet[ARP].pdst,
            "protocol": "ARP"
        }
        print("\033[94mSEND PACKET INFO:\033[0m", sent_packet_info)

        sendp(sent_packet, iface="lo")

        # Wait for packet to be captured
        time.sleep(1)

        # Capture output of ipk-sniffer
        sniffer_output = capture_output(sniffer_process)

        # Parse captured packet information
        captured_packet_info = parse_captured_packet(sniffer_output)
        print("\033[93mCAPTURED PACKET INFO:\033[0m", captured_packet_info)

        # Compare packet information
        for key, value in sent_packet_info.items():
            assert captured_packet_info.get(key) == value, f"{key} mismatch"

        print_passed("ARP packet test passed successfully")

    except Exception as e:
        print_failed("ARP packet test failed")
        print(e)

    finally:
        # Stop the sniffer
        stop_sniffer(sniffer_process)


def test_send_icmpv6_packet():
    """
    Test sending an ICMPv6 packet and capturing it with ipk-sniffer.
    """
    try:
        # Start the sniffer
        sniffer_process = start_sniffer("lo", ["--icmp6", "-n", "1"])

        # Wait for the sniffer to initialize
        time.sleep(1)

        # Send ICMPv6 packet
        sent_packet, packet_len = send_icmpv6_packet()
        
        # Save sent packet information
        sent_packet_info = {
            #"src_mac": sent_packet[Ether].src,
            #"dst_mac": sent_packet[Ether].dst,
            "frame length": packet_len,
            "src IP": sent_packet[IPv6].src,
            "dst IP": sent_packet[IPv6].dst,
            "protocol": "ICMPv6"
        }
        print("\033[94mSEND PACKET INFO:\033[0m", sent_packet_info)

        sendp(sent_packet, iface="lo")

        # Wait for packet to be captured
        time.sleep(1)

        # Capture output of ipk-sniffer
        sniffer_output = capture_output(sniffer_process)

        # Parse captured packet information
        captured_packet_info = parse_captured_packet(sniffer_output)
        print("\033[93mCAPTURED PACKET INFO:\033[0m", captured_packet_info)

        # Compare packet information
        for key, value in sent_packet_info.items():
            assert captured_packet_info.get(key) == value, f"{key} mismatch"

        print_passed("ICMPv6 packet test passed successfully")

    except Exception as e:
        print_failed("ICMPv6 packet test failed")
        print(e)

    finally:
        # Stop the sniffer
        stop_sniffer(sniffer_process)


def test_send_icmpv4_packet():
    """
    Test sending an ICMPv4 packet and capturing it with ipk-sniffer.
    """
    try:
        # Start the sniffer
        sniffer_process = start_sniffer("lo", ["--icmp4", "-n", "1"])

        # Wait for the sniffer to initialize
        time.sleep(1)

        # Send ICMPv4 packet
        sent_packet, packet_len = send_icmpv4_packet()
        
        # Save sent packet information
        sent_packet_info = {
            #"src_mac": sent_packet[Ether].src,
            #"dst_mac": sent_packet[Ether].dst,
            "frame length": packet_len,
            "src IP": sent_packet[IP].src,
            "dst IP": sent_packet[IP].dst,
            "protocol": "ICMPv4"
        }
        print("\033[94mSEND PACKET INFO:\033[0m", sent_packet_info)

        sendp(sent_packet, iface="lo")

        # Wait for packet to be captured
        time.sleep(1)

        # Capture output of ipk-sniffer
        sniffer_output = capture_output(sniffer_process)

        # Parse captured packet information
        captured_packet_info = parse_captured_packet(sniffer_output)
        print("\033[93mCAPTURED PACKET INFO:\033[0m", captured_packet_info)

        # Compare packet information
        for key, value in sent_packet_info.items():
            assert captured_packet_info.get(key) == value, f"{key} mismatch"

        print_passed("ICMPv4 packet test passed successfully")

    except Exception as e:
        print_failed("ICMPv4 packet test failed:")
        print(e)

    finally:
        # Stop the sniffer
        stop_sniffer(sniffer_process)


if __name__ == "__main__":
    # Run the tests
    test_send_tcp_packet()
    print('____________________________________________________________________________________________________________________________________')
    test_send_udp_packet()
    print('____________________________________________________________________________________________________________________________________')
    test_send_arp_packet()
    print('____________________________________________________________________________________________________________________________________')
    test_send_icmpv6_packet()
    print('____________________________________________________________________________________________________________________________________')
    test_send_icmpv4_packet()
    print('____________________________________________________________________________________________________________________________________')
