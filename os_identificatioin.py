### FINDING TTL & WINDOW SIZE VALUES
from scapy.all import *
from flask import Flask, request, jsonify


def get_ttl_and_window_size(pcap_file):
    # Dictionary to store TTL and window size for each device (MAC address)
    device_info = {}

    # Iterate through each packet in the pcap file
    for packet in pcap_file:
        # Check if the packet has an IP layer
        if IP in packet:
            ip_layer = packet[IP]
            source_mac = packet.src

            # Extract TTL value from IP header
            ttl = ip_layer.ttl

            # Check if the packet also has a TCP layer for window size
            if TCP in packet:
                tcp_layer = packet[TCP]
                window_size = tcp_layer.window

                # Update device information
                if source_mac not in device_info:
                    device_info[source_mac] = {'TTL': ttl, 'Window_Size': window_size}
                else:
                    # If the device already exists, update the TTL and window size if necessary
                    if ttl > device_info[source_mac]['TTL']:
                        device_info[source_mac]['TTL'] = ttl

                    if 'Window_Size' in device_info[source_mac] and window_size > device_info[source_mac]['Window_Size']:
                        device_info[source_mac]['Window_Size'] = window_size
                    elif 'Window_Size' not in device_info[source_mac]:
                        device_info[source_mac]['Window_Size'] = window_size
            # If the packet doesn't have a TCP layer, only update the TTL value
            else:
                if source_mac not in device_info:
                    device_info[source_mac] = {'TTL': ttl}
                else:
                    if ttl > device_info[source_mac]['TTL']:
                        device_info[source_mac]['TTL'] = ttl

    return device_info


# UPLOAD_FOLDER = 'C:\\Users\\A_R_COMPUTERS\\OneDrive\\Desktop\\FYP\\server\\PCAP'

# pcap_file = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

# device_info = get_ttl_and_window_size(pcap_file)

# # # Print device information
# # for mac_address, info in device_info.items():
# #     print("MAC Address:", mac_address)
# #     print("TTL:", info.get('TTL'))
# #     print("Window Size:", info.get('Window_Size', "N/A"))
# #     print()

# # Storing the output in a dictionary
# output_dict = device_info

# print(output_dict)

