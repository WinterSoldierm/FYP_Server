# from flask import jsonify
# import os
# import pandas as pd
# from scapy.all import rdpcap, Ether, IP
# import manuf

# UPLOAD_FOLDER = 'C:\\Users\\A_R_COMPUTERS\\OneDrive\\Desktop\\FYP\\server\\PCAP'

# def perform_mac_ip_vendor_mapping(pcap_file_path):
#     manuf_db = manuf.MacParser()
#     mac_ip_vendor_mapping = {}
#     vendor = {}
#     ip_address_mapping = {}

#     packets = rdpcap(pcap_file_path)
#     for packet in packets:
#         if Ether in packet:
#             src_mac = packet[Ether].src
#             dst_mac = packet[Ether].dst
#             if IP in packet:
#                 src_ip = packet[IP].src
#                 dst_ip = packet[IP].dst
#                 ip_address_mapping.setdefault(src_mac, set()).add(src_ip)
#                 ip_address_mapping.setdefault(dst_mac, set()).add(dst_ip)
#                 vendor[src_mac] = manuf_db.get_manuf(src_mac)
#                 vendor[dst_mac] = manuf_db.get_manuf(dst_mac)

#     for mac in ip_address_mapping:
#         mac_ip_vendor_mapping[mac] = {"IP": list(ip_address_mapping[mac]), "Vendors": vendor.get(mac, "Unknown")}
        
#     print(mac_ip_vendor_mapping)

#     return mac_ip_vendor_mapping


# # def load_ot_vendor_prefixes(vendor_DB_path):
# #     # Load vendor database from CSV file
# #     vendor_DB = pd.read_csv(vendor_DB_path)

# #     # Extract OT vendor prefixes
# #     ot_vendor_prefixes = set()
# #     for prefix in vendor_DB['macPrefix']:
# #         ot_vendor_prefixes.add(prefix.lower())  # Convert to lowercase for case-insensitive comparison

# #     return ot_vendor_prefixes

# def extract_mac_prefixes(mac_ip_vendor_mapping):
#     mac_prefixes = []
#     for mac in mac_ip_vendor_mapping:
#         mac_prefix = ':'.join(mac.split(':')[:3]).lower()
#         mac_prefixes.append(mac_prefix)
#     return mac_prefixes


# # def perform_device_classification(mac_ip_vendor_mapping, vendor_DB_path):
# #     # Load OT vendor prefixes
# #     ot_vendor_prefixes = load_ot_vendor_prefixes(vendor_DB_path)
# #     mac_prefix = extract_mac_prefixes(mac_ip_vendor_mapping)

# #     print(mac_prefix)

# #     for device, info in mac_ip_vendor_mapping.items():
# #         # Extract MAC address prefix
# #         mac_prefix = device.split(':')[0].lower()  # Extracting the MAC address prefix
    
# #         # Classify device based on MAC address prefix
# #         if mac_prefix in ot_vendor_prefixes:
# #             info['category'] = 'OT'
# #         else:
# #             info['category'] = 'IT'

# #     return mac_ip_vendor_mapping

# class TrieNode:
#     def __init__(self):
#         self.children = {}
#         self.is_end_of_word = False


# def load_ot_vendor_prefixes(vendor_DB_path):
#     # Load vendor database from CSV file
#     vendor_DB = pd.read_csv(vendor_DB_path)

#     # Initialize trie root
#     ot_vendor_trie = TrieNode()

#     # Insert OT vendor prefixes into trie
#     for prefix in vendor_DB['macPrefix']:
#         insert_into_trie(ot_vendor_trie, prefix.lower())

#     return ot_vendor_trie


# def insert_into_trie(root, prefix):
#     node = root
#     for char in prefix:
#         if char not in node.children:
#             node.children[char] = TrieNode()
#         node = node.children[char]
#     node.is_end_of_word = True

# # def perform_device_classification(mac_ip_vendor_mapping, vendor_DB_path):
# #     # Load OT vendor prefixes trie
# #     ot_vendor_trie = load_ot_vendor_prefixes(vendor_DB_path)

# #     # Extract MAC address prefixes
# #     mac_prefixes = extract_mac_prefixes(mac_ip_vendor_mapping)

# #     for mac_prefix in mac_prefixes:
# #         # Classify device based on MAC address prefix
# #         if is_prefix_in_trie(ot_vendor_trie, mac_prefix):
# #             info['category'] = 'OT'
# #         else:
# #             info['category'] = 'IT'

# #     return mac_ip_vendor_mapping


# def perform_device_classification(mac_ip_vendor_mapping, vendor_DB_path):
#     # Load OT vendor prefixes trie
#     ot_vendor_trie = load_ot_vendor_prefixes(vendor_DB_path)

#     # Extract MAC address prefixes
#     mac_prefixes = extract_mac_prefixes(mac_ip_vendor_mapping)

#     for mac, info in mac_ip_vendor_mapping.items():  # Corrected loop variable
#         # Extract MAC address prefix
#         mac_prefix = mac.split(':')[0].lower()  # Extracting the MAC address prefix
    
#         # Classify device based on MAC address prefix
#         if is_prefix_in_trie(ot_vendor_trie, mac_prefix):
#             info['category'] = 'OT'
#         else:
#             info['category'] = 'IT'

#     return mac_ip_vendor_mapping


# def is_prefix_in_trie(trie, prefix):
#     node = trie
#     for char in prefix:
#         if char not in node.children:
#             return False
#         node = node.children[char]
#     return node.is_end_of_word





from flask import jsonify
import os
import pandas as pd
from scapy.all import rdpcap, Ether, IP
import manuf

UPLOAD_FOLDER = 'C:\\Users\\A_R_COMPUTERS\\OneDrive\\Desktop\\FYP\\server\\PCAP'

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False

def insert_into_trie(root, prefix):
    node = root
    for char in prefix:
        if char not in node.children:
            node.children[char] = TrieNode()
        node = node.children[char]
    node.is_end_of_word = True

def is_prefix_in_trie(trie, prefix):
    node = trie
    for char in prefix:
        if char not in node.children:
            return False
        node = node.children[char]
    return node.is_end_of_word

def perform_mac_ip_vendor_mapping(pcap_file_path):
    manuf_db = manuf.MacParser()
    mac_ip_vendor_mapping = {}
    vendor = {}
    ip_address_mapping = {}

    packets = rdpcap(pcap_file_path)
    for packet in packets:
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ip_address_mapping.setdefault(src_mac, set()).add(src_ip)
                ip_address_mapping.setdefault(dst_mac, set()).add(dst_ip)
                vendor[src_mac] = manuf_db.get_manuf(src_mac)
                vendor[dst_mac] = manuf_db.get_manuf(dst_mac)

    for mac in ip_address_mapping:
        mac_ip_vendor_mapping[mac] = {"IP": list(ip_address_mapping[mac]), "Vendors": vendor.get(mac, "Unknown")}

    # print(mac_ip_vendor_mapping)

    return mac_ip_vendor_mapping

def extract_mac_prefixes(mac_ip_vendor_mapping):
    mac_prefixes = []
    for mac in mac_ip_vendor_mapping:
        mac_prefix = ':'.join(mac.split(':')[:3]).lower()
        mac_prefixes.append(mac_prefix)
    return mac_prefixes


def load_ot_vendor_prefixes(vendor_DB_path):
    # Load vendor database from CSV file
    vendor_DB = pd.read_csv(vendor_DB_path)

    # Initialize trie root
    ot_vendor_trie = TrieNode()

    # Insert OT vendor prefixes into trie
    for prefix in vendor_DB['macPrefix']:
        insert_into_trie(ot_vendor_trie, prefix.lower())

    return ot_vendor_trie

def perform_device_classification(mac_ip_vendor_mapping, vendor_DB_path):
    # Load OT vendor prefixes trie
    ot_vendor_trie = load_ot_vendor_prefixes(vendor_DB_path)

    # Extract MAC address prefixes
    # mac_prefixes = extract_mac_prefixes(mac_ip_vendor_mapping)

    for mac, info in mac_ip_vendor_mapping.items():  # Corrected loop variable
        # Extract MAC address prefix
        mac_prefix = ':'.join(mac.split(':')[:3]).lower()  # Extracting the MAC address prefix
        # print(mac_prefix)

        # Classify device based on MAC address prefix
        if is_prefix_in_trie(ot_vendor_trie, mac_prefix):
            info['category'] = 'OT'
        else:
            info['category'] = 'IT'

    return mac_ip_vendor_mapping


# def perform_mac_vendor_mapping(pcap_file_path):
#     manuf_db = manuf.MacParser()
#     mac_vendor_mapping = {}
#     vendor = {}

#     packets = rdpcap(pcap_file_path)
#     for packet in packets:
#         if Ether in packet:
#             src_mac = packet[Ether].src
#             dst_mac = packet[Ether].dst
#             vendor[src_mac] = manuf_db.get_manuf(src_mac)
#             vendor[dst_mac] = manuf_db.get_manuf(dst_mac)

#     return mac_vendor_mapping