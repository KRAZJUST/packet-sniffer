import subprocess
import time
from scapy.all import Ether, IP, TCP, sendp

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
    # Return the packet
    return tcp_packet

def send_udp_packet():
    """"
    Send a UDP packet.
    """
    udp_packet = Ether() / IP(dst="192.168.0.39")

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
            key, value = parts[0].strip(), parts[1].strip()
            packet_info[key] = value
    return packet_info


def test_send_tcp_packet():
    """
    Test sending a TCP packet and capturing it with ipk-sniffer.
    """
    try:
        # Start the sniffer
        sniffer_process = start_sniffer("wlp1s0", ["--tcp", "-n", "1"])

        # Wait for the sniffer to initialize
        time.sleep(1)

        # Send TCP packet
        sent_packet = send_tcp_packet()
        sendp(sent_packet, iface="wlp1s0")

        # Wait for packet to be captured
        time.sleep(1)

        # Capture output of ipk-sniffer
        sniffer_output = capture_output(sniffer_process)
        print(sniffer_output)

        # Parse captured packet information
        captured_packet_info = parse_captured_packet(sniffer_output)

        #Compare packet information
        for key in captured_packet_info:
            if key in sent_packet.fields:
                assert sent_packet.getfieldval(key) == captured_packet_info[key], f"{key} mismatch"

        print("TCP packet test passed successfully")

    except Exception as e:
        print("TCP packet test failed:", e)

    finally:
        # Stop the sniffer
        stop_sniffer(sniffer_process)

if __name__ == "__main__":
    # Run the test
    test_send_tcp_packet()
