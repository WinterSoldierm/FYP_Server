from flask import Flask, request, jsonify
import manuf
from scapy.all import rdpcap, Ether, IP


def find_unique_mac_addresses(pcap_file):
    packets = rdpcap(pcap_file)
    mac_add_list_src = set(packet[0].src for packet in packets)
    mac_add_list_dst = set(packet[0].dst for packet in packets)
    unique_mac_addresses = set(mac_add_list_src.union(mac_add_list_dst))
    # unique_mac_addresses.discard('ff:ff:ff:ff:ff:ff')``
    return unique_mac_addresses

def get_mac_vendor_mapping(pcap_file):
    manuf_db = manuf.MacParser()
    mac_ip_vendor_mapping = {}
    vendor = {}
    ip_address_mapping = {}

    # Find unique MAC addresses
    unique_mac_addresses = set()

    packets = rdpcap(pcap_file)
    
    for packet in packets:
        if 'Ether' in packet:
            unique_mac_addresses.add(packet['Ether'].src)
            unique_mac_addresses.add(packet['Ether'].dst)

    # Get vendor information for each MAC address
    for add in unique_mac_addresses:
        vendor[add] = manuf_db.get_manuf_long(add)

    # Find corresponding IP addresses for each MAC address
    for packet in packets:
        if 'Ether' in packet and 'IP' in packet:
            src_mac = packet['Ether'].src
            dst_mac = packet['Ether'].dst
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst

            if src_mac not in ip_address_mapping:
                ip_address_mapping[src_mac] = set()
            if dst_mac not in ip_address_mapping:
                ip_address_mapping[dst_mac] = set()
            ip_address_mapping[src_mac].add(src_ip)
            ip_address_mapping[dst_mac].add(dst_ip)
            vendor[src_mac] = manuf_db.get_manuf_long(src_mac)
            vendor[dst_mac] = manuf_db.get_manuf_long(dst_mac)

    # Store the results in the dictionary
    for mac in ip_address_mapping:
        mac_ip_vendor_mapping[mac] = {"IP": list(ip_address_mapping[mac]), "Vendor": vendor.get(mac, "Unknown")}

    return mac_ip_vendor_mapping

