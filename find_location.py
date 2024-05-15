from flask import Flask, jsonify
from scapy.all import rdpcap, Ether, IP

def perform_mac_ip_mapping(packets):
    ip_addresses = set()

    
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_addresses.add(src_ip)
            ip_addresses.add(dst_ip)

    return list(ip_addresses)