# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import os
# import manuf
# from scapy.all import rdpcap, Ether

# app = Flask(__name__)
# CORS(app)

# UPLOAD_FOLDER = 'C:\\Users\\A_R_COMPUTERS\\OneDrive\\Desktop\\FYP\\server\\PCAP'
# ALLOWED_EXTENSIONS = {'pcap'}

# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# def get_file_path(filename):
#     return os.path.join(app.config['UPLOAD_FOLDER'], filename)

# @app.route('/')
# def hello():
#     return 'Hello from the Python backend!'

# @app.route('/upload', methods=['POST'])
# def upload_file():
#     try:
#         if 'file' not in request.files:
#             return jsonify({'error': 'No file part'}), 400

#         file = request.files['file']

#         if file.filename == '':
#             return jsonify({'error': 'No selected file'}), 400

#         if file and allowed_file(file.filename):
#             file_path = get_file_path('uploaded.pcap')
#             file.save(file_path)
#             return jsonify({'success': 'File uploaded successfully'}), 200
#         else:
#             return jsonify({'error': 'Invalid file type'}), 400
#     except Exception as e:
#         return jsonify({'error': f'Error during file upload: {str(e)}'}), 500

# @app.route('/mac-oui-lookup', methods=["GET", "POST"])
# def mac_oui_lookup():
#     try:
#         file_path = get_file_path('uploaded.pcap')

#         manuf_db = manuf.MacParser()
#         vendor = {}

#         pcap_file = rdpcap(file_path)
#         for packet in pcap_file:
#             if packet.haslayer(Ether):
#                 add = packet[Ether].src
#                 vendor[add] = manuf_db.get_manuf(add)

#         return jsonify({'success': 'MAC OUI lookup successful', 'mac_lookup': vendor}), 200
#     except Exception as e:
#         return jsonify({'error': f'Error performing MAC OUI lookup: {str(e)}'}), 500

# if __name__ == '__main__':
#     app.run(debug=True)





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



app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'C:\\Users\\A_R_COMPUTERS\\OneDrive\\Desktop\\FYP\\server\\PCAP'
ALLOWED_EXTENSIONS = {'pcap'}

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
        

# def process_uploaded_file(file_path):
#     # Identify industrial protocols
#     ip_protocol_count = identify_industrial_protocols(file_path)

#     # Perform MAC OUI lookup
#     mac_lookup_data = mac_oui_lookup(file_path)

#     return ip_protocol_count, mac_lookup_data


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

# @app.route('/upload', methods=['POST'])
# def upload_file():
#     try:
#         if 'file' not in request.files:
#             return jsonify({'error': 'No file part'}), 400

#         file = request.files['file']

#         if file.filename == '':
#             return jsonify({'error': 'No selected file'}), 400

#         if file and allowed_file(file.filename):
#             file_path = get_file_path('uploaded.pcap')
#             file.save(file_path)

#             # Identify industrial protocols
#             ip_protocol_count = identify_industrial_protocols(file_path)

#             # Perform MAC OUI lookup
#             mac_lookup_data = mac_oui_lookup(file_path)

#             # Return both sets of data along with the success message
#             return jsonify({'success': 'File uploaded successfully', 'ip_protocol_count': ip_protocol_count, 'mac_lookup_data': mac_lookup_data}), 200
#         else:
#             return jsonify({'error': 'Invalid file type'}), 400
#     except Exception as e:
#         return jsonify({'error': f'Error during file upload: {str(e)}'}), 500

# @app.route('/upload', methods=['POST'])
# def upload_file():
#     try:
#         if 'file' not in request.files:
#             return jsonify({'error': 'No file part'}), 400

#         file = request.files['file']

#         if file.filename == '':
#             return jsonify({'error': 'No selected file'}), 400

#         if file and allowed_file(file.filename):
#             secure_filename(file.filename)  # Use secure_filename to avoid security issues
#             file_path = get_file_path('uploaded.pcap')

#             with file.stream as stream:
#                 # Save the file using streaming
#                 with open(file_path, 'wb') as f:
#                     for chunk in stream:
#                         f.write(chunk)

#             # Use executor to run file processing tasks asynchronously
#             future = executor.submit(process_uploaded_file, file_path)

#             # Return a response without waiting for the tasks to complete
#             return jsonify({'success': 'File upload started successfully'}), 200
#         else:
#             return jsonify({'error': 'Invalid file type'}), 400
#     except Exception as e:
#         return jsonify({'error': f'Error during file upload: {str(e)}'}), 500


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
                vendor[add] = manuf_db.get_manuf(add)

        return jsonify({'success': 'MAC OUI lookup successful', 'mac_lookup': vendor}), 200
    except Exception as e:
        return jsonify({'error': f'Error performing MAC OUI lookup: {str(e)}'}), 500
    
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
        file_path = get_file_path('uploaded.pcap')
        packets = rdpcap(file_path)

        active_macs = set()
        for packet in packets:
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                active_macs.add(src_mac)
                active_macs.add(dst_mac)

        return jsonify({'active_devices': list(active_macs)}), 200
    except Exception as e:
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

            node_trace = go.Scatter(
                x=[],
                y=[],
                text=list(ip_set),
                mode='markers',
                hoverinfo='text',
                marker=dict(
                    size=15,
                    color='skyblue'
                )
            )

            edge_trace = go.Scatter(
                x=[],
                y=[],
                line=dict(width=0.5, color='gray'),
                hoverinfo='none',
                mode='lines'
            )

            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_trace['x'] += (x0,)
                edge_trace['x'] += (x1,)
                edge_trace['x'] += (None,)  # Add None for line segment

                edge_trace['y'] += (y0,)
                edge_trace['y'] += (y1,)
                edge_trace['y'] += (None,)  # Add None for line segment

            for node in G.nodes():
                x, y = pos[node]
                node_trace['x'] += (x,)
                node_trace['y'] += (y,)

            fig = go.Figure(data=[edge_trace, node_trace],
                            layout=go.Layout(
                                title='Layer 1 Network Topology',
                                showlegend=False,
                                margin=dict(b=20),
                                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                            ))

            return jsonify({'success': 'Network topology generated successfully', 'figure': fig.to_json()}), 200
        except Exception as e:
            return jsonify({'error': f'Error generating network topology: {str(e)}'}), 500
        


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
        mac_ip_vendor_mapping[mac] = {"IP": list(ip_address_mapping[mac]), "Vendor": vendor.get(mac, "Unknown")}

    return mac_ip_vendor_mapping

def perform_device_classification(mac_ip_vendor_mapping, vendor_DB):
    for device in mac_ip_vendor_mapping:
        vendor = mac_ip_vendor_mapping[device]['Vendor']
        if vendor in vendor_DB['Vendor'].values:
            category = vendor_DB[vendor_DB['Vendor'] == vendor]['Category'].iloc[0]
            mac_ip_vendor_mapping[device]['category'] = category
        else:
            mac_ip_vendor_mapping[device]['category'] = 'Unknown'

    return mac_ip_vendor_mapping

@app.route('/device-classification', methods=['GET'])
def device_classification():
    try:
        pcap_file_path = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

        if not os.path.isfile(pcap_file_path):
            return jsonify({'error': 'No pcap file uploaded'}), 404

        mac_ip_vendor_mapping = perform_mac_ip_vendor_mapping(pcap_file_path)

        vendor_DB = {}  # Update with your vendor database
        classified_devices = perform_device_classification(mac_ip_vendor_mapping, vendor_DB)

        return jsonify({'success': 'Device classification successful', 'classified_devices': classified_devices}), 200
    except Exception as e:
        return jsonify({'error': f'Error during device classification: {str(e)}'}), 500


if __name__ == "__main__":
    app.run(debug=True)









