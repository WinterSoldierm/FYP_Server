from scapy.all import *
from scapy.all import rdpcap, IP, TCP, UDP, Ether

def find_unique_mac_addresses(pcap_file):
    packets = rdpcap(pcap_file)
    mac_add_list_src = set(packet[0].src for packet in packets)
    mac_add_list_dst = set(packet[0].dst for packet in packets)
    unique_mac_addresses = set(mac_add_list_src.union(mac_add_list_dst))
    unique_mac_addresses.discard('ff:ff:ff:ff:ff:ff')
    return unique_mac_addresses

def extract_ports_separate(pcap_file, unique_mac_addresses):
    # Define dictionaries for storing port numbers
    src_ports_mapping = {}
    dst_ports_mapping = {}
    packets = rdpcap(pcap_file)
    # Loop through the packets
    for packet in packets:
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            if src_mac not in unique_mac_addresses and dst_mac not in unique_mac_addresses:
                continue
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = None
                dst_port = None
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                # Store the port numbers
                if src_mac not in src_ports_mapping:
                    src_ports_mapping[src_mac] = set()
                if dst_mac not in dst_ports_mapping:
                    dst_ports_mapping[dst_mac] = set()
                src_ports_mapping[src_mac].add(src_port)
                dst_ports_mapping[dst_mac].add(dst_port)

    # Return the port mappings
    return src_ports_mapping, dst_ports_mapping

def extract_ports_combined(pcap_file, unique_mac_addresses):
    # Define a dictionary for storing port numbers
    port_mapping = {}
    packets = rdpcap(pcap_file)
    # Loop through the packets
    for packet in packets:
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                port = None
                if TCP in packet:
                    port = packet[TCP].sport
                elif UDP in packet:
                    port = packet[UDP].sport
                # Store the port number
                if src_mac not in port_mapping:
                    port_mapping[src_mac] = set()
                port_mapping[src_mac].add(port)
                if dst_mac not in port_mapping:
                    port_mapping[dst_mac] = set()
                port_mapping[dst_mac].add(port)

    # Return the port mapping
    return port_mapping

# Example usage:
# src_ports_mapping, dst_ports_mapping = extract_ports_separate(pcap_file, unique_mac_addresses)
# port_mapping = extract_ports_combined(pcap_file, unique_mac_addresses)
