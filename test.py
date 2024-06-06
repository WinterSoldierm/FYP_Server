@app.route('/process_pcap', methods=['GET'])
def process_pcap():
    global protocols_for_device_classification

    pcap_file_path = os.path.join(UPLOAD_FOLDER, 'uploaded.pcap')

    if not os.path.exists(pcap_file_path):
        return jsonify({'error': 'PCAP file not found'}), 404

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.FileCapture(pcap_file_path)
    unique_mac_addresses = find_unique_mac_addresses(pcap_file_path)
    
    protocols_by_mac = {mac: set() for mac in unique_mac_addresses}
    
    for packet in capture:
        if hasattr(packet, 'eth'):
            mac_address = packet.eth.src
            if mac_address in protocols_by_mac:
                if protocols_by_mac[mac_address] == "Unknown":
                    protocols_by_mac[mac_address] = set()
                for layer in packet.layers:
                    protocols_by_mac[mac_address].add(layer.layer_name)

    capture.close()
    
    protocols_by_mac = {mac: list(protocols) for mac, protocols in protocols_by_mac.items()}
    protocols_for_device_classification = protocols_by_mac
    
    return jsonify(protocols_by_mac)