from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import manuf
from scapy.all import rdpcap, IP, TCP, UDP, Ether
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor
import plotly.express as px
import networkx as nx
import plotly.graph_objects as go
import pandas as pd
from dbConnection import connect_to_mongodb
from login import login_bp
import csv
from device_clssification import  perform_device_classification,perform_mac_ip_vendor_mapping
from find_location import perform_mac_ip_mapping
from os_identificatioin import get_ttl_and_window_size
from flask import Flask, render_template
import plotly.graph_objs as go
from activityChart import calculate_sorted_device_appearance_count,find_unique_mac_addresses
from PortNumber import extract_ports_combined, extract_ports_separate,find_unique_mac_addresses
from macOUILookUp import get_mac_vendor_mapping
from flask_session import Session
import pyshark 
import asyncio
import requests
from bs4 import BeautifulSoup
import subprocess

app = Flask(__name__)
CORS(app)

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'  # You can choose the session storage type
app.config['SECRET_KEY'] = '211070903'  # Replace this with a secret key for session encryption

# Initialize Flask-Session
Session(app)

@app.route('/')
def index():
    # Connect to MongoDB
    client = connect_to_mongodb()
    if client:
        # Perform operations using the client
        # Example: collection = client.mydatabase.mycollection
        return "Connected to MongoDB!"
    else:
        return "Failed to connect to MongoDB!"
    
# Register the login blueprint with the Flask application
app.register_blueprint(login_bp, url_prefix='/auth')


UPLOAD_FOLDER = 'C:\\Users\\A_R_COMPUTERS\\OneDrive\\Desktop\\FYP\\server\\PCAP'
ALLOWED_EXTENSIONS = {'pcap','pcapng'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
executor = ThreadPoolExecutor()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_path(filename):
    return os.path.join(app.config['UPLOAD_FOLDER'], filename)

def identify_industrial_protocols(pcap_file_path):
    packets = rdpcap(pcap_file_path)
    ip_protocol_count = {}

    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            payload = packet.payload

            if TCP in payload:
                dport = payload[TCP].dport
                sport = payload[TCP].sport
                protocol = identify_protocol_by_port(dport, sport)

            elif UDP in payload:
                dport = payload[UDP].dport
                sport = payload[UDP].sport
                protocol = identify_protocol_by_port(dport, sport)

            else:
                protocol = "Non-TCP/IP"

            update_protocol_count(ip_protocol_count, ip_src, protocol)
            update_protocol_count(ip_protocol_count, ip_dst, protocol)

    return ip_protocol_count

def identify_protocol_by_port(dport, sport):
    if dport == 502 or sport == 502:
        return "Modbus"
    elif dport == 20000 or sport == 20000:
        return "DNP3"
    elif dport == 1883 or sport == 1883 or dport == 8883 or sport == 8883:
        return "MQTT"
    elif dport == 2404 or sport == 2404:
        return "IEC 60870-5"
    elif dport == 44818 or sport == 44818:
        return "EtherNet/IP"
    elif dport == 34964 or sport == 34964:
        return "PROFINET"
    elif dport == 47808 or sport == 47808:
        return "BACnet"
    elif dport == 135 or sport == 135:
        return "OPC"
    elif dport == 102 or sport == 102:
        return "S7COMM"
    else:
        return "Unknown"

def update_protocol_count(ip_protocol_count, ip, protocol):
    if ip in ip_protocol_count:
        if protocol in ip_protocol_count[ip]:
            ip_protocol_count[ip][protocol] += 1
        else:
            ip_protocol_count[ip][protocol] = 1
    else:
        ip_protocol_count[ip] = {protocol: 1}


def mac_oui_lookup(pcap_file_path):
    oui_data = {}

    def extract_mac_address(packet):
        if Ether in packet:
            return packet[Ether].src.lower()

    packets = rdpcap(pcap_file_path)
    
    def get_vendor(mac_address):
        manuf_db = manuf.MacParser()
        return manuf_db.get_manuf(mac_address)

    for packet in packets:
        mac_address = extract_mac_address(packet)
        if mac_address:
            vendor = get_vendor(mac_address)

            if vendor != "Unknown":
                update_oui_data(oui_data, mac_address, vendor)

    return oui_data

def update_oui_data(oui_data, mac_address, vendor):
    if mac_address not in oui_data:
        oui_data[mac_address] = vendor
        
def process_uploaded_file(file_path):
    ip_protocol_count = identify_industrial_protocols(file_path)
    mac_lookup_data = mac_oui_lookup(file_path)
    return ip_protocol_count, mac_lookup_data
        

def update_protocol_Distribution_count(protocol_count, protocol):
    if protocol in protocol_count:
        protocol_count[protocol] += 1
    else:
        protocol_count[protocol] = 1
        
def generate_protocol_distribution_data(pcap_file_path):
    packets = rdpcap(pcap_file_path)
    protocol_count = {}

    for packet in packets:
        payload = packet.payload

        if TCP in payload:
            protocol = identify_protocol_by_port(payload[TCP].dport, payload[TCP].sport)
            update_protocol_Distribution_count(protocol_count, protocol)

        elif UDP in payload:
            protocol = identify_protocol_by_port(payload[UDP].dport, payload[UDP].sport)
            update_protocol_Distribution_count(protocol_count, protocol)

    labels = list(protocol_count.keys())
    values = list(protocol_count.values())

    return {'labels': labels, 'values': values}

# Routes 
@app.route('/')
def hello():
    return 'Hello from the Python backend!'

# Mac and IP lookup multithreading
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file and allowed_file(file.filename):
            secure_filename(file.filename)
            file_path = get_file_path('uploaded.pcap')

            with file.stream as stream:
                with open(file_path, 'wb') as f:
                    for chunk in stream:
                        f.write(chunk)

            # Use executor to run file processing tasks concurrently
            future = executor.submit(process_uploaded_file, file_path)
            return jsonify({'success': 'File upload started successfully'}), 200
        else:
            return jsonify({'error': 'Invalid file type'}), 400
    except Exception as e:
        return jsonify({'error': f'Error during file upload: {str(e)}'}), 500


@app.route('/mac-oui-lookup', methods=["GET", "POST"])
def perform_mac_oui_lookup():
    try:
        file_path = get_file_path('uploaded.pcap')

        manuf_db = manuf.MacParser()
        vendor = {}

        pcap_file = rdpcap(file_path)
        for packet in pcap_file:
            if packet.haslayer(Ether):
                add = packet[Ether].src
                vendor[add] = manuf_db.get_manuf_long(add)

        return jsonify({'success': 'MAC OUI lookup successful', 'mac_lookup': vendor}), 200
    except Exception as e:
        return jsonify({'error': f'Error performing MAC OUI lookup: {str(e)}'}), 500
    
@app.route('/mac-vendor-lookup', methods=['POST'])
def mac_vendor_lookup():
    pcap_file =  os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')
    # Process the pcap file and extract MAC vendor mapping
    # Assuming pcap_file is in a suitable format, such as a list of packets
    mac_ip_vendor_mapping = get_mac_vendor_mapping(pcap_file)

    return jsonify(mac_ip_vendor_mapping)   
    
# Add this route to your backend code
@app.route('/ip-protocol-lookup', methods=['POST'])
def perform_ip_protocol_lookup():
    print('route hit')
    try:
        file_path = get_file_path('uploaded.pcap')

        # Identify industrial protocols
        ip_protocol_count = identify_industrial_protocols(file_path)

        return jsonify({'success': 'IP and Protocol lookup successful', 'ip_protocol_count': ip_protocol_count}), 200
    except Exception as e:
        return jsonify({'error': f'Error performing IP and Protocol lookup: {str(e)}'}), 500


@app.route('/generate-protocol-distribution', methods=['POST'])
def generate_protocol_distribution():
    try:
        file_path = get_file_path('uploaded.pcap')
        protocol_distribution_data = generate_protocol_distribution_data(file_path)
        return jsonify({'success': 'Protocol Distribution generated successfully', 'protocolData': protocol_distribution_data}), 200
    except Exception as e:
        return jsonify({'error': f'Error generating Protocol Distribution: {str(e)}'}), 500


@app.route('/active_devices', methods=['POST'])
def active_devices():
    try:
        # Get the file path of the uploaded pcap file
        file_path = get_file_path('uploaded.pcap')
        
        # Read the pcap file
        packets = rdpcap(file_path)

        # Extract unique MAC addresses from source and destination fields in packets
        mac_add_list_src = set(packet[0].src for packet in packets)
        mac_add_list_dst = set(packet[0].dst for packet in packets)

        # Combine unique source and destination MAC addresses
        unique_mac_addresses = set(mac_add_list_src.union(mac_add_list_dst))

        # Remove Broadcast Addresses
        if 'ff:ff:ff:ff:ff:ff' in unique_mac_addresses:
            unique_mac_addresses.remove('ff:ff:ff:ff:ff:ff')

        # Initialize lists to store active and inactive MAC addresses
        inactive_devices = []
        active_devices = []

        # Iterate over each packet in the pcap file
        for packet in packets:
            # Check if the packet contains Ethernet header
            if Ether in packet:
                # Extract source MAC address
                src_mac = packet[Ether].src
                # Check if the source MAC address is in the unique list of MAC addresses
                if src_mac in unique_mac_addresses:
                    active_devices.append(src_mac)
                else:
                    inactive_devices.append(src_mac)

        # Return the list of active and inactive devices as JSON response
        return jsonify({'active_devices': list(set(active_devices)), 'inactive_devices': list(set(inactive_devices))}), 200
    except Exception as e:
        # Return error message if any exception occurs
        return jsonify({'error': f'Error retrieving active devices: {str(e)}'}), 500

@app.route('/generate-network-topology', methods=['GET', 'POST'])
def generate_network_topology():
    if request.method == 'GET':
        # Check if a pcap file has been uploaded
        if os.path.isfile(get_file_path('uploaded.pcap')):
            return jsonify({'success': 'PCAP file uploaded'}), 200
        else:
            return jsonify({'error': 'No PCAP file uploaded'}), 404
    elif request.method == 'POST':
        try:
            file_path = get_file_path('uploaded.pcap')
            if not os.path.isfile(file_path):
                return jsonify({'error': 'No PCAP file uploaded'}), 404
            
            pcap_file = rdpcap(file_path)
            
            ip_set = set()
            edges = []
            for packet in pcap_file:
                if packet.haslayer(IP):  # Ensure IP layer exists
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    ip_set.add(ip_src)
                    ip_set.add(ip_dst)
                    edges.append((ip_src, ip_dst))  # Add edge as a tuple
            
            edges = list(set(edges))  # Ensure each edge appears only once
            
            G = nx.Graph()
            G.add_nodes_from(ip_set)
            G.add_edges_from(edges)

            pos = nx.spring_layout(G)

            # Creating Node and Edge Data for Plotly
            nodes_data = [{'id': node, 'x': pos[node][0], 'y': pos[node][1]} for node in G.nodes()]
            links_data = [{'source': edge[0], 'target': edge[1]} for edge in G.edges()]

            response_data = {
                'nodes': nodes_data,
                'links': links_data,
                'message': 'Network topology generated successfully'
            }

            return jsonify(response_data), 200
        except Exception as e:
            return jsonify({'error': f'Error generating network topology: {str(e)}'}), 500
  
# @app.route('/device-classification', methods=['POST'])
# def device_classification():
#     try:
#         pcap_file_path = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

#         if not os.path.isfile(pcap_file_path):
#             return jsonify({'error': 'No pcap file uploaded'}), 404

#         mac_ip_vendor_mapping = perform_mac_ip_vendor_mapping(pcap_file_path)

#         # Path to the vendor database CSV file
#         vendor_DB_path = os.path.join(UPLOAD_FOLDER, 'mac vendor.csv')

#         classified_devices = perform_device_classification(mac_ip_vendor_mapping, vendor_DB_path)

#         return jsonify({'success': 'Device classification successful', 'classified_devices': classified_devices}), 200
#     except Exception as e:
#         return jsonify({'error': f'Error during device classification: {str(e)}'}), 500

@app.route('/ip_address', methods=['GET'])
def get_ip_addresses():
    pcap_file_path = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')
    ip_addresses = perform_mac_ip_mapping(pcap_file_path)
    return jsonify(ip_addresses)
    
@app.route('/os_identification', methods=['POST'])
def os_identification():
    pcap_file = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

    # Your OS mapping dictionary
    os_mapping = {
        (32, 8192): "Windows 95",
        (25, 4128): "iOS 12.4 (Cisco Routers)",
        (64, 8760): "Solaris 7",
        (64, 16384): "AIX 4.3",
        (64, 8192): ["Windows 95", "Linux (Kernel 3.2)", "BlueArc Titan 2100 NAS device", "Cisco IOS (12.4)", "NetApp Filer (Data ONTAP 7.2)", "Juniper ScreenOS", "IBM z/OS", "Cisco ASA (Adaptive Security Appliance)"],
        (64, 5840): ["Linux (Kernel 2.4 and 2.6)","Debian Linux", "Red Hat Enterprise Linux"],
        (64, 5720): ["Google Linux", "Google's customized Linux"],
        (64, 65535): "FreeBSD",
        (64, 501): "Linux Ubuntu 10.04",
        (64, 65520): "OpenBSD",
        (64, 12800): "Linux (Kernel 4.4)",
        (64, 16384): "AIX 5.3",
        (64, 14600): "Linux (Kernel 3.10)",
        (128, 8192): ["Windows Vista", "Windows 7", "Windows Server 2008", "HP-UX 11.11","Windows 8", "Windows Server 2012 R2","Windows 8.1", "Windows Server 2012 R2","Windows 10", "Windows Server 2016"],
        (128, 16384): ["Windows Server 2000", "Microsoft Windows XP SP3", "Windows 7", "Windows Server 2012", "Windows Vista","CentOS 7"],
        (128, 65535): ["Windows XP", "Ubuntu Linux"],
        (128, 16384): ["Windows Server 2016", "Windows 10"],
        (128, 29200): "MacOS X 10.10",
        (128, 32120): "MacOS X 10.15",
        (255, 65535): "FreeBSD 10",
        (255, 8760): "Solaris 7",
        (255, 4128): "Cisco iOS 12.4",
        (255, 64240): "Solaris 10",
    }
    
    # Process the pcap file
    packet_list = rdpcap(pcap_file)
    device_info = get_ttl_and_window_size(packet_list)

    # OS Identification using the new mapping logic
    for mac_address in device_info:
        # Initialize list for OS for each MAC address
        device_info[mac_address]['OS'] = []

        # Check if 'Window_Size' and 'TTL' subkeys exist
        if 'Window_Size' in device_info[mac_address] and 'TTL' in device_info[mac_address]:
            ttl = device_info[mac_address]['TTL']
            window_size = device_info[mac_address]['Window_Size']

            # Check if the TTL and Window_Size combination exists in the mapping
            if (ttl, window_size) in os_mapping:
                os_names = os_mapping[(ttl, window_size)]
                if isinstance(os_names, list):
                    device_info[mac_address]['OS'].extend(os_names)
                else:
                    device_info[mac_address]['OS'].append(os_names)
            else:
                device_info[mac_address]['OS'].append("Unknown")
        else:
            # If either 'Window_Size' or 'TTL' subkey is missing, mark the OS as "Unknown"
            device_info[mac_address]['OS'].append("Unknown")

    # Return the OS information as JSON response
    return jsonify(device_info)

@app.route('/activity_data', methods=['GET'])
def get_activity_data():
    # Load pcap_file, you might need to adjust this part to load your pcap_file
    pcap_file = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

    # Calculate sorted device appearance count
    unique_mac_addresses = find_unique_mac_addresses(pcap_file)
    sorted_device_appearance_count = calculate_sorted_device_appearance_count(unique_mac_addresses, pcap_file)

    # Format data as JSON
    activity_data = [{'mac_address': mac, 'count': count} for mac, count in sorted_device_appearance_count.items()]

    return jsonify(activity_data)


@app.route('/find_ports', methods=['POST'])
def find_ports():
    pcap_file = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')
    try:
        # Find unique MAC addresses
        unique_mac_addresses = find_unique_mac_addresses(pcap_file)

        # # Extract port mappings
        # port_mapping = extract_ports_combined(pcap_file, unique_mac_addresses)
        
        # port_mapping = {mac: list(ports) for mac, ports in port_mapping.items()}
        # # Return the port mappings as JSON response
        # return jsonify(port_mapping)
        
        
        # Extract port mappings separately
        src_ports_mapping, dst_ports_mapping = extract_ports_separate(pcap_file, unique_mac_addresses)

        # Convert sets to lists
        src_ports_mapping = {mac: list(ports) for mac, ports in src_ports_mapping.items()}
        dst_ports_mapping = {mac: list(ports) for mac, ports in dst_ports_mapping.items()}

        # Return the port mappings as JSON response
        return jsonify({'src_ports_mapping': src_ports_mapping, 'dst_ports_mapping': dst_ports_mapping})


    except Exception as e:
        # Handle any errors that occur during processing
        return jsonify({'error': str(e)}), 500


# def find_unique_mac_addresses(pcap_file):
#     packets = rdpcap(pcap_file)
#     mac_add_list_src = set(packet[0].src for packet in packets)
#     mac_add_list_dst = set(packet[0].dst for packet in packets)
#     unique_mac_addresses = set(mac_add_list_src.union(mac_add_list_dst))
#     unique_mac_addresses.discard('ff:ff:ff:ff:ff:ff')  # Optional: Remove broadcast address
#     return list(unique_mac_addresses)  # Convert the set to a list

# @app.route('/process_pcap', methods=['GET'])
# def process_pcap():
#     pcap_file_path = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

#     if not os.path.exists(pcap_file_path):
#         return jsonify({'error': 'PCAP file not found'}), 404

#     # Set up a new event loop for PyShark
#     loop = asyncio.new_event_loop()
#     asyncio.set_event_loop(loop)

#     capture = pyshark.FileCapture(pcap_file_path)
#     unique_mac_addresses = find_unique_mac_addresses(pcap_file_path)
    
#     protocols_by_mac = {mac: set() for mac in unique_mac_addresses}
    
#     for packet in capture:
#         if hasattr(packet, 'eth'):
#             mac_address = packet.eth.src
#             if mac_address in protocols_by_mac:
#                 for layer in packet.layers:
#                     protocols_by_mac[mac_address].add(layer.layer_name)

#     capture.close()

#     protocols_by_mac = {mac: list(protocols) for mac, protocols in protocols_by_mac.items()}
    
#     return jsonify(protocols_by_mac)


# def find_unique_mac_addresses(pcap_file):
#     packets = rdpcap(pcap_file)
#     mac_add_list_src = set(packet[0].src for packet in packets)
#     mac_add_list_dst = set(packet[0].dst for packet in packets)
#     unique_mac_addresses = set(mac_add_list_src.union(mac_add_list_dst))
#     unique_mac_addresses.discard('ff:ff:ff:ff:ff:ff')  # Optional: Remove broadcast address
#     return list(unique_mac_addresses)  # Convert the set to a list

# protocols_for_device_classification = {}

# @app.route('/process_pcap', methods=['GET'])
# def process_pcap():
#     pcap_file_path = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

#     if not os.path.exists(pcap_file_path):
#         return jsonify({'error': 'PCAP file not found'}), 404

#     # Set up a new event loop for PyShark
#     loop = asyncio.new_event_loop()
#     asyncio.set_event_loop(loop)

#     capture = pyshark.FileCapture(pcap_file_path)
#     unique_mac_addresses = find_unique_mac_addresses(pcap_file_path)
    
#     protocols_by_mac = {mac: set() for mac in unique_mac_addresses}
    
#     # for packet in capture:
#     #     if hasattr(packet, 'eth'):
#     #         mac_address = packet.eth.src
#     #         if mac_address in protocols_by_mac:
#     #             for layer in packet.layers:
#     #                 protocols_by_mac[mac_address].add(layer.layer_name)
    
#     for packet in capture:
#             # Extract MAC address
#             if hasattr(packet, 'eth'):
#                 mac_address = packet.eth.src

#                 # If MAC address is in the unique list, collect protocols
#                 if mac_address in protocols_by_mac:
#                     if protocols_by_mac[mac_address] == "Unknown":
#                         protocols_by_mac[mac_address] = set()
#                     # Iterate over packet layers and collect protocol names
#                     for layer in packet.layers:
#                         protocols_by_mac[mac_address].add(layer.layer_name)


#     capture.close()
    
#     protocols_by_mac = {mac: list(protocols) for mac, protocols in protocols_by_mac.items()}
    
#     return jsonify(protocols_by_mac)









# # List of OT protocols
# ot_protocols_keywords = [
#     'Modbus', 'DNP3', 'OPC UA', 'ProfiNet', 'EtherNet/IP', 'BACnet', 'CAN', 'IEC 60870-5-104',
#     'S7comm', 'OPC DA', 'EtherCAT', 'NFS', 'CIP', 'CIPCM', 'HART', 'Profinet-IRT', 'FOUNDATION Fieldbus',
#     'DeviceNet', 'ASi', 'CC-Link', 'LON', 'PROFIBUS', 'SERCOS', 'M-Bus', 'Modbus TCP',
#     'Modbus IP', 'EtherCAT', 'POWERLINK', 'FF-HSE', 'IEC 61850', 'IEEE 1588', 'WirelessHART',
#     'ISA100.11a', 'Zigbee',
#     'IEC 60870-5-101', 'IEC 61850-8-1', 'IEC 61400-25', 'IEC 60870-6', 'IEC 61850-9-2', 'IEC 60870-6-TASE.2',
#     'IEC 61400-25', 'DNP3 Secure Authentication (DNP3SA)', 'IEC 61158', 'IEC 62351', 'IEC 62056',
#     'ISO/IEC 7816', 'IEC 62351', 'PROFINET RT', 'PROFINET IRT', 'PROFINET IO', 'PROFINET CBA',
#     'PROFINET MRP', 'PROFINET MRPD', 'PROFINET MRPV', 'PROFINET MRPW', 'PROFINET DCP',
#     'PROFINET SNMP', 'PROFINET LLDP', 'PROFINET DCP', 'PROFINET GSDML', 'PROFINET XML',
#     'PROFINET FDL', 'PROFINET I&M', 'PROFINET IO-Link', 'CC-Link IE', 'CC-Link IE Control',
#     'CC-Link Safety', 'CC-Link IE Motion', 'CC-Link IE Field', 'CC-Link IE Field Safety',
#     'BACnet/IP', 'BACnet/MSTP', 'BACnet/IPv6', 'BACnet Ethernet', 'BACnet MS/TP', 'BACnet PTP',
#     'BACnet B/IPv6', 'CIP Safety', 'CIP Motion', 'CIP Energy', 'CIP Sync', 'CIP Security'
# ]

# ot_protocols_keywords_lower = [protocol.lower() for protocol in ot_protocols_keywords]

# def classify_devices_by_protocol(protocols_by_mac):
#     it_ot_classification = {}
#     serial = 1

#     # Iterate through the original dictionary
#     for mac_address, protocols in protocols_by_mac.items():
#         if protocols == 'Unknown':
#             classification = 'Unknown'
#             protocol_list = set()
#         else:
#             # Convert the set of protocols to lowercase for case-insensitive comparison
#             protocol_list = {protocol.lower() for protocol in protocols}

#             # Determine if any of the protocols are in the OT protocols list
#             classification = 'OT' if any(protocol in ot_protocols_keywords_lower for protocol in protocol_list) else 'IT'

#         # Add the new entry to the result dictionary
#         it_ot_classification[mac_address] = classification
#         serial += 1

#     return it_ot_classification

# @app.route('/device-classification', methods=['POST'])
# def device_classification():
#     try:
#         pcap_file_path = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

#         if not os.path.isfile(pcap_file_path):
#             return jsonify({'error': 'No pcap file uploaded'}), 404


#         # New classification based on protocols
#         new_classifications = classify_devices_by_protocol(protocols_for_device_classification)

#         result = {
#             'success': 'Device classification successful',
#             'new_classifications': new_classifications
#         }

#         return jsonify(result), 200
#     except Exception as e:
#         return jsonify({'error': f'Error during device classification: {str(e)}'}), 500




# Protocol Identification
protocols_for_device_classification = {} # Global Protocol Dictionary





@app.route('/protocols-by-mac', methods=['GET'])
def get_protocols_by_mac():
    global protocols_for_device_classification
    pcap_file = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')
    unique_mac_addresses = find_unique_mac_addresses(pcap_file)
    protocols_by_mac = {}
    protocols_by_mac = {mac: "Unknown" for mac in unique_mac_addresses}
    
    tshark_path = 'C:\\Program Files\\Wireshark\\tshark.exe' 
    # Run the tshark command and capture the output
    tshark_command = [
        tshark_path,
        '-r', pcap_file,
        '-T', 'fields',
        '-e', 'eth.src',
        '-e', 'frame.protocols'
    ]
    result = subprocess.run(tshark_command, capture_output=True, text=True)

    # Process the output
    for line in result.stdout.splitlines():
        try:
            mac_address, protocols = line.split('\t')
            if mac_address in protocols_by_mac:
                protocol_list = protocols.split(':')
                if protocols_by_mac[mac_address] == "Unknown":
                    protocols_by_mac[mac_address] = set()
                for protocol in protocol_list:
                    protocols_by_mac[mac_address].add(protocol)
        except ValueError:
            # Skip lines that don't have the expected number of fields
            continue

    # Convert sets to lists for JSON serialization
    protocols_by_mac = {mac: list(protocols) if isinstance(protocols, set) else protocols for mac, protocols in protocols_by_mac.items()}
    protocols_for_device_classification = protocols_by_mac
    return jsonify(protocols_by_mac)





ot_protocols_keywords = [
    'Modbus', 'DNP3', 'OPC UA', 'ProfiNet', 'EtherNet/IP', 'BACnet', 'CAN', 'IEC 60870-5-104',
    'S7comm', 'OPC DA', 'EtherCAT', 'NFS', 'CIP', 'CIPCM', 'HART', 'Profinet-IRT', 'FOUNDATION Fieldbus',
    'DeviceNet', 'ASi', 'CC-Link', 'LON', 'PROFIBUS', 'SERCOS', 'M-Bus', 'Modbus TCP',
    'Modbus IP', 'EtherCAT', 'POWERLINK', 'FF-HSE', 'IEC 61850', 'IEEE 1588', 'WirelessHART',
    'ISA100.11a', 'Zigbee',
    'IEC 60870-5-101', 'IEC 61850-8-1', 'IEC 61400-25', 'IEC 60870-6', 'IEC 61850-9-2', 'IEC 60870-6-TASE.2',
    'IEC 61400-25', 'DNP3 Secure Authentication (DNP3SA)', 'IEC 61158', 'IEC 62351', 'IEC 62056',
    'ISO/IEC 7816', 'IEC 62351', 'PROFINET RT', 'PROFINET IRT', 'PROFINET IO', 'PROFINET CBA',
    'PROFINET MRP', 'PROFINET MRPD', 'PROFINET MRPV', 'PROFINET MRPW', 'PROFINET DCP',
    'PROFINET SNMP', 'PROFINET LLDP', 'PROFINET DCP', 'PROFINET GSDML', 'PROFINET XML',
    'PROFINET FDL', 'PROFINET I&M', 'PROFINET IO-Link', 'CC-Link IE', 'CC-Link IE Control',
    'CC-Link Safety', 'CC-Link IE Motion', 'CC-Link IE Field', 'CC-Link IE Field Safety',
    'BACnet/IP', 'BACnet/MSTP', 'BACnet/IPv6', 'BACnet Ethernet', 'BACnet MS/TP', 'BACnet PTP',
    'BACnet B/IPv6', 'CIP Safety', 'CIP Motion', 'CIP Energy', 'CIP Sync', 'CIP Security'
]

ot_protocols_keywords_lower = [protocol.lower() for protocol in ot_protocols_keywords]

# def find_unique_mac_addresses(pcap_file):
#     packets = rdpcap(pcap_file)
#     mac_add_list_src = set(packet[Ether].src for packet in packets if Ether in packet)
#     mac_add_list_dst = set(packet[Ether].dst for packet in packets if Ether in packet)
#     unique_mac_addresses = set(mac_add_list_src.union(mac_add_list_dst))
#     # unique_mac_addresses.discard('ff:ff:ff:ff:ff:ff')  # Optional: Remove broadcast address
#     return list(unique_mac_addresses)  # Convert the set to a list

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

    return mac_ip_vendor_mapping

def classify_devices_by_protocol(protocols_by_mac):
    it_ot_classification = {}
    serial = 1

    for mac_address, protocols in protocols_by_mac.items():
        if protocols == 'Unknown':
            classification = 'Unknown'
            protocol_list = set()
        else:
            protocol_list = {protocol.lower() for protocol in protocols}
            classification = 'OT' if any(protocol in ot_protocols_keywords_lower for protocol in protocol_list) else 'IT'

        it_ot_classification[mac_address] = classification
        serial += 1

    return it_ot_classification



@app.route('/device-classification', methods=['POST'])
def device_classification():
    global protocols_for_device_classification

    try:
        if not protocols_for_device_classification:
            return jsonify({'error': 'No protocols data available for classification'}), 404

        mac_ip_vendor_mapping = perform_mac_ip_vendor_mapping(os.path.join(UPLOAD_FOLDER, 'uploaded.pcap'))
        new_classifications = classify_devices_by_protocol(protocols_for_device_classification)

        classified_devices = {}
        for mac, classification in new_classifications.items():
            classified_devices[mac] = {
                "IP": mac_ip_vendor_mapping.get(mac, {}).get("IP", []),
                "Vendors": mac_ip_vendor_mapping.get(mac, {}).get("Vendors", "Unknown"),
                "category": classification
            }

        result = {
            'success': 'Device classification successful',
            'classified_devices': classified_devices
        }

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': f'Error during device classification: {str(e)}'}), 500

# Define a route for fetching IP addresses
@app.route('/ip-addresses', methods=['GET'])
def fetch_ip_addresses():
    # Assuming pcap_file is available and contains the packets
    pcap_file = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')
    packets = rdpcap(pcap_file)
    ip_address_mapping = {}
    serial = 1

    # Replace pcap_file with your actual packet data source
    for packet in packets:
        if 'Ether' in packet:
            src_mac = packet['Ether'].src
            dst_mac = packet['Ether'].dst
            if 'IP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                if src_mac not in ip_address_mapping:
                    ip_address_mapping[src_mac] = set()
                if dst_mac not in ip_address_mapping:
                    ip_address_mapping[dst_mac] = set()
                ip_address_mapping[src_mac].add(src_ip)
                ip_address_mapping[dst_mac].add(dst_ip)

    # Prepare the response data
    response_data = []
    for mac in ip_address_mapping:
        ip_set = list(ip_address_mapping[mac])  # Convert set to list
        response_data.append({
            "MAC": mac,
            "IPs": ip_set
        })

    return jsonify(response_data)







device_cve_info = {}

def get_mac_vendor_mapping(pcap_file_path):
    manuf_db = manuf.MacParser()
    mac_vendor_mapping = {}
    unique_mac = find_unique_mac_addresses(pcap_file_path)  # Assuming you have implemented find_unique_mac_addresses
    for mac_address in unique_mac:
        vendor = manuf_db.get_manuf_long(mac_address)
        mac_vendor_mapping[mac_address] = vendor
    return mac_vendor_mapping

def get_cve_data(vendor):
    url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=" + vendor + "&search_type=all&isCpeNameSearch=false"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    table = soup.find("table", class_="table table-striped table-hover")

    vuln_id = None
    summary = None
    cvss_severity = None
    for row in table.find_all("tr")[1:]:
        vuln_id_cell = row.find("a")
        summary_cell = row.find("p")
        cvss_severity_cell = row.find("a", class_="label")

        if vuln_id_cell:
            vuln_id = vuln_id_cell.text
        if summary_cell:
            summary = summary_cell.text
        if cvss_severity_cell:
            cvss_severity = cvss_severity_cell.text

    return vuln_id, summary, cvss_severity

@app.route('/device-cve-info', methods=['GET'])
def get_device_cve_info():
    pcap_file = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')
    mac_vendor_mapping = get_mac_vendor_mapping(pcap_file)
    for mac in mac_vendor_mapping:
        # print(mac)
        Vendor = str(mac_vendor_mapping[mac])
        # print(Vendor)
        device_cve_info[mac] = {
            "Vendor": Vendor,
            "CVE ID": get_cve_data(Vendor)[0],
            "Summary": get_cve_data(Vendor)[1],
            "Severity Score": get_cve_data(Vendor)[2]
        }
    
    # for mac in device_cve_info:
    #     print(mac, device_cve_info[mac])

    return jsonify(device_cve_info)






if __name__ == "__main__":
    app.run(debug=True)











