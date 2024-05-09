from flask import Flask, jsonify
from scapy.all import rdpcap, Ether, IP

def perform_mac_ip_mapping(pcap_file_path):
    ip_addresses = set()

    packets = rdpcap(pcap_file_path)
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_addresses.add(src_ip)
            ip_addresses.add(dst_ip)

    return list(ip_addresses)