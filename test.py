import pyshark
from scapy.all import rdpcap

pcap_file = 'C:\\Users\\A_R_COMPUTERS\\Downloads\\Plant1.pcap'
capture = pyshark.FileCapture(pcap_file)

protocols_by_mac = {}


def find_unique_mac_addresses(pcap_file):
    packets = rdpcap(pcap_file)
    mac_add_list_src = set(packet[0].src for packet in packets)
    mac_add_list_dst = set(packet[0].dst for packet in packets)
    unique_mac_addresses = set(mac_add_list_src.union(mac_add_list_dst))
    unique_mac_addresses.discard('ff:ff:ff:ff:ff:ff')  # Optional: Remove broadcast address
    return list(unique_mac_addresses)  # Convert the set to a list  


unique_mac_addresses = find_unique_mac_addresses(pcap_file)

# Initialize the dictionary with empty sets for each MAC address
for mac in unique_mac_addresses:
    protocols_by_mac[mac] = set()

# Iterate through packets
for packet in capture:
    # Extract MAC address
    mac_address = packet.eth.src

    # Iterate over packet layers and collect protocol names
    for layer in packet.layers:
        protocols_by_mac[mac_address].add(layer.layer_name)

# Print protocols for each MAC address
for mac, protocols in protocols_by_mac.items():
    print(f"MAC: {mac}, Protocols: {', '.join(protocols)}")
print(len(protocols_by_mac))