from flask import Flask, render_template
import plotly.graph_objs as go
from scapy.all import *

# Function to find unique MAC addresses
def find_unique_mac_addresses(pcap_file):
    packets = rdpcap(pcap_file)
    mac_add_list_src = set(packet[0].src for packet in packets)
    mac_add_list_dst = set(packet[0].dst for packet in packets)
    unique_mac_addresses = set(mac_add_list_src.union(mac_add_list_dst))
    unique_mac_addresses.discard('ff:ff:ff:ff:ff:ff')
    return unique_mac_addresses

# Function to calculate sorted device appearance count
def calculate_sorted_device_appearance_count(unique_mac_addresses, pcap_file):
    packets = rdpcap(pcap_file)
    device_appearance_count = {mac_address: 0 for mac_address in unique_mac_addresses}
    for mac_address in unique_mac_addresses:
        for packet in packets:
            if 'Ether' in packet:
                src_mac = packet['Ether'].src
                dst_mac = packet['Ether'].dst
                if mac_address == src_mac or mac_address == dst_mac:
                    device_appearance_count[mac_address] += 1
    return dict(sorted(device_appearance_count.items(), key=lambda x: x[1], reverse=True))


# # Route to generate activity chart
# @app.route('/activity_chart', methods=['POST'])
# def activity_chart():
#     # Load pcap_file, you might need to adjust this part to load your pcap_file
#     pcap_file = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

#     # Calculate sorted device appearance count
#     unique_mac_addresses = find_unique_mac_addresses(pcap_file)
#     sorted_device_appearance_count = calculate_sorted_device_appearance_count(unique_mac_addresses, pcap_file)

#     # Extract MAC addresses and counts
#     mac_addresses = list(sorted_device_appearance_count.keys())
#     counts = list(sorted_device_appearance_count.values())

#     # Create a bar trace
#     bar_trace = go.Bar(
#         x=mac_addresses,
#         y=counts,
#         marker=dict(color='skyblue')
#     )

#     # Create layout with zooming and panning enabled
#     layout = go.Layout(
#         title='Count of MAC Addresses',
#         xaxis=dict(title='MAC Address'),
#         yaxis=dict(title='Count'),
#         dragmode='zoom',  # Enable zooming and panning
#     )

#     # Create figure
#     fig = go.Figure(data=[bar_trace], layout=layout)

#     # Convert the plotly figure to HTML
#     chart_html = fig.to_html(full_html=False)

#     return render_template('activity_chart.html', chart_html=chart_html)
