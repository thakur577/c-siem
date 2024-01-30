import psutil
import pyshark
import pytz
from datetime import datetime
import binascii
import socket
import json
import configparser
import sys

config = configparser.ConfigParser()
config.read('netflow.ini')

# fetch tcp_host and tcp_port properties from netflow.ini file
tcp_host = config['netflow']['tcp_host']
tcp_port = config['netflow']['tcp_port']

if tcp_host is None or tcp_host == "" or tcp_port is None or tcp_port == "":
    print("Please populate 'tcp_host' and 'tcp_port' properties with values in 'netflow.ini' file.")
    sys.exit(0)  # Exit with a status code (0 for success)
else:
    print("tcp_host:"+str(tcp_host))
    print("tcp_port:" + str(tcp_port))

def hex_dump_to_ascii(hex_dump):
    # Remove any spaces or other separators from the hex dump
    hex_dump = ''.join(hex_dump.split(':'))
    # Convert the hex dump to bytes
    try:
        byte_data = binascii.unhexlify(hex_dump)
        # Decode the bytes to ASCII using 'utf-8' or 'latin-1'
        ascii_text = byte_data.decode('utf-8')  # You can also try 'latin-1'
        return ascii_text
    except binascii.Error:
        return "Invalid hex dump"
    except UnicodeDecodeError:
        return "Unable to decode as ASCII"

def send_json_over_tcp(host, port, data):
    try:
        # Create a TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Connect to the specified host and port
            s.connect((host, int(port)))
            # Convert the JSON data to a string
            json_str = json.dumps(data)
            # Send the JSON data
            s.sendall(json_str.encode('utf-8'))
            print(f"JSON data sent to Socket: {host}:{port} : data sent: {json_str}")
    except Exception as e:
        print(f"Error: {e}")

def convert_utc_to_ist(utc_timestamp):
    # Convert UTC timestamp to a datetime object
    utc_datetime = datetime.utcfromtimestamp(utc_timestamp)
    # Add fractions of seconds
    utc_datetime_with_fractions = utc_datetime.replace(microsecond=int((utc_timestamp % 1) * 1e6))
    # Define UTC and IST time zones
    utc_timezone = pytz.timezone('UTC')
    ist_timezone = pytz.timezone('Asia/Kolkata')  # IST is the time zone for India
    # Convert UTC datetime to IST datetime
    ist_datetime = utc_datetime_with_fractions.replace(tzinfo=utc_timezone).astimezone(ist_timezone)
    return ist_datetime

# Function to get a list of available network interfaces
def get_available_interfaces():
    try:
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
        return []

def process_packet(packet):
    print("---------------------------------------------------------------------------------------------------------------------------")
    print("packet.layers: ", packet.layers)
    print("packet.length: ", packet.length)
    #print("packet._packet_string: ", packet._packet_string)
    #print("packet.frame_info: ", packet.frame_info)
    #print("packet.captured_length: ", packet.captured_length)
    print("packet.highest_layer: ", packet.highest_layer)
    #print("packet.interface_captured: ", packet.interface_captured)
    #print("packet.show: ", packet.show)
    #print("packet.number: ", packet.number)
    print("packet.sniff_time: ", packet.sniff_time)
    #print("packet.sniff_timestamp: ", packet.sniff_timestamp)

    # print("packet start :--------------------------------------------------------------------------------------------------")
    # print("packet string: ",str(packet))
    # print("packet end :--------------------------------------------------------------------------------------------------")
    if hasattr(packet, 'ip') and hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
        #print(""" if hasattr(packet, 'ip') and hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst') """)
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        # Access the IP layer
        ip_layer = packet['IP']
        # Access the 'len' field in the IP layer, which represents the total length of the IP packet
        total_length = int(ip_layer.len)
        print(f"IP Total Length: {total_length}")

        if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'):
            #print(""" if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'): """)
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport

            type_of_service = ""
            num_bytes = ""
            num_packets = ""
            if hasattr(packet.ip, 'proto'):
                protocol_number = int(packet.ip.proto)
                if protocol_number == 17:
                    protocol_type = "udp"

            if hasattr(packet.ip, 'tos'):
                type_of_service = packet.ip.tos
            else:
                type_of_service = "Not Available"

            if hasattr(packet, 'sniff_timestamp'):
                timestamp = packet.sniff_timestamp
                timestamp = int(float(timestamp))
                timestamp = convert_utc_to_ist(timestamp)

            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port},Layer 3 Protocol Type: {protocol_type},Type of Service (ToS): {type_of_service},Ingress Interface: {packet.interface_captured},Timestamp: {timestamp},Number of Bytes: {num_bytes}, Number of Packets: {num_packets}")
            udp_json = {
                "src_ip":src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol" : protocol_type,
                "timestamp": str(timestamp),
                "packet_length": total_length
            }
            # send json over tcp
            send_json_over_tcp(tcp_host,tcp_port,udp_json)

            # Check if the payload is present
            if hasattr(packet.udp, 'payload'):
                # Extract and print the payload (NetFlow data)
                netflow_data = packet.udp.payload
                #print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}")
                print(f"NetFlow Data UDP: {netflow_data}")
                ascii_string = hex_dump_to_ascii(netflow_data)
                print(f"ascii_string: {ascii_string}")

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
            #print(""" if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'): """)
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            # Access the TCP layer
            tcp_layer = packet['TCP']
            # Access the 'flags' field in the TCP layer, which represents the TCP control flags
            flags_value = int(tcp_layer.flags, 16)  # Convert the hexadecimal value to an integer
            print("TCP Flag Value:"+str(flags_value))

            # Define TCP flag values
            urg = (flags_value & 0x20) >> 5
            print("TCP Flag urg:" + str(urg))
            ack = (flags_value & 0x10) >> 4
            print("TCP Flag ack:" + str(ack))
            psh = (flags_value & 0x08) >> 3
            print("TCP Flag psh:" + str(psh))
            rst = (flags_value & 0x04) >> 2
            print("TCP Flag rst:" + str(rst))
            syn = (flags_value & 0x02) >> 1
            print("TCP Flag syn:" + str(syn))
            fin = flags_value & 0x01
            print("TCP Flag fin:" + str(fin))


            num_bytes = ""
            num_packets = ""
            if hasattr(packet.ip, 'proto'):
                protocol_number = int(packet.ip.proto)
                if protocol_number == 6:
                    protocol_type = "tcp"

            if hasattr(packet.ip, 'tos'):
                type_of_service = packet.ip.tos
            else:
                type_of_service = "Not Available"

            if hasattr(packet, 'sniff_timestamp'):
                timestamp = packet.sniff_timestamp
                timestamp = int(float(timestamp))
                timestamp = convert_utc_to_ist(timestamp)

            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port},Layer 3 Protocol Type: {protocol_type},Type of Service (ToS): {type_of_service},Ingress Interface: {packet.interface_captured},Timestamp: {timestamp},Number of Bytes: {num_bytes}, Number of Packets: {num_packets}")
            tcp_json = {
                "src_ip":src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol" : protocol_type,
                "timestamp": str(timestamp),
                "packet_length": total_length
            }
            # send json over tcp
            send_json_over_tcp(tcp_host,tcp_port,tcp_json)

            # Check if the payload is present
            if hasattr(packet.tcp, 'payload'):
                # Extract and print the payload (NetFlow data)
                netflow_data = packet.tcp.payload
                #print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}")
                print(f"NetFlow Data TCP: {netflow_data}")
                ascii_string = hex_dump_to_ascii(netflow_data)
                print(f"ascii_string: {ascii_string}")

    # Check if the packet has a ICMPv6 layer
    if 'ICMPv6' in packet:
        # Access the ICMPv6 layer
        icmpv6_layer = packet.icmpv6
        print("packet.icmpv6:", packet.icmpv6)
        # print("dir() function on packet.icmpv6:", dir(packet.icmpv6))
        print("ICMPv6 Type:", icmpv6_layer.type)
        print("ICMPv6 Code:", icmpv6_layer.code)

    # Check if the packet has a TLS layer
    if 'TLS' in packet:
        # Access the TLS layer
        tls_layer = packet.tls
        print("packet.tls:",packet.tls)
        # print("dir() function on packet.tls:", dir(packet.tls))
    else:
        print("'TLS' not in packet")

    # Check if the packet has a TLS layer
    if 'TCP' in packet:
        # Access the TCP layer
        tcp_layer = packet.tcp
        print("packet.tcp:",packet.tcp)
        #print("dir() function on packet.tcp:", dir(packet.tcp))
    else:
        print("'TCP' not in packet")

    # Check if the packet has a UDP layer
    if 'UDP' in packet:
        # Access the TCP layer
        tcp_layer = packet.udp
        print("packet.udp:",packet.udp)
        #print("dir() function on packet.udp:", dir(packet.udp))
    else:
        print("'UDP' not in packet")

    # Check if the packet has a SSDP layer
    if 'SSDP' in packet:
        # Access the SSDP layer
        ssdp_layer = packet.ssdp
        print("packet.ssdp:",packet.ssdp)
        #print("dir() function on packet.ssdp:", dir(packet.ssdp))
    else:
        print("'SSDP' not in packet")

    # Check if the packet has a SNMP layer
    if 'SNMP' in packet:
        # Access the SNMP layer
        snmp_layer = packet.snmp
        print("packet.snmp:",packet.snmp)
        #print("dir() function on packet.snmp:", dir(packet.snmp))
    else:
        print("'SNMP' not in packet")

    # Check if the packet has a ARP layer
    if 'ARP' in packet:
        # Access the ARP layer
        arp_layer = packet.arp
        print("packet.arp:",packet.arp)
        #print("dir() function on packet.arp:", dir(packet.arp))
    else:
        print("'ARP' not in packet")

    # Check if the packet has a DNS layer
    if 'DNS' in packet:
        # Access the DNS layer
        dns_layer = packet.dns
        print("packet.dns:",packet.dns)
        #print("dir() function on packet.dns:", dir(packet.dns))
    else:
        print("'DNS' not in packet")

    # Check if the packet has an IPv6 layer
    if 'IPv6' in packet:
        # Access the IPv6 layer
        ipv6_layer = packet.ipv6
        print("packet.ipv6:", packet.ipv6)
        # print("dir() function on packet.ipv6:", dir(packet.ipv6))
    else:
        print("'IPv6' not in packet")

    # Check if the packet has an MDNS layer
    if 'MDNS' in packet:
        # Access the MDNS layer
        mdns_layer = packet.mdns
        print("packet.mdns:", packet.mdns)
        # print("dir() function on packet.mdns:", dir(packet.mdns))
    else:
        print("'MDNS' not in packet")

    # Check if the packet has an VRRP layer
    if 'VRRP' in packet:
        # Access the VRRP layer
        vrrp_layer = packet.vrrp
        print("packet.vrrp:", packet.vrrp)
        # print("dir() function on packet.vrrp:", dir(packet.vrrp))
    else:
        print("'VRRP' not in packet")

    # Check if the packet has an STP layer
    if 'STP' in packet:
        # Access the STP layer
        stp_layer = packet.stp
        print("packet.stp:", packet.stp)
        # print("dir() function on packet.stp:", dir(packet.stp))
    else:
        print("'STP' not in packet")

    # Check if the packet has an LLDP layer
    if 'LLDP' in packet:
        # Access the LLDP layer
        lldp_layer = packet.lldp
        print("packet.lldp:", packet.lldp)
        # print("dir() function on packet.lldp:", dir(packet.lldp))
    else:
        print("'LLDP' not in packet")

    # Check if the packet has an DHCP layer
    if 'DHCP' in packet:
        # Access the DHCP layer
        dhcp_layer = packet.dhcp
        print("packet.dhcp:", packet.dhcp)
        # print("dir() function on packet.dhcp:", dir(packet.dhcp))
    else:
        print("'DHCP' not in packet")

    # Check if the packet has an DHCPV6 layer
    if 'DHCPV6' in packet:
        # Access the DHCPV6 layer
        dhcpv6_layer = packet.dhcpv6
        print("packet.dhcpv6:", packet.dhcpv6)
        # print("dir() function on packet.dhcpv6:", dir(packet.dhcpv6))
    else:
        print("'DHCPV6' not in packet")

    # Check if the packet has an LLMNR layer
    if 'LLMNR' in packet:
        # Access the LLMNR layer
        llmnr_layer = packet.llmnr
        print("packet.llmnr:", packet.llmnr)
        # print("dir() function on packet.llmnr:", dir(packet.llmnr))
    else:
        print("'LLMNR' not in packet")

    # Check if the packet has an NTP layer
    if 'NTP' in packet:
        # Access the NTP layer
        ntp_layer = packet.ntp
        print("packet.ntp:", packet.ntp)
        # print("dir() function on packet.ntp:", dir(packet.ntp))
    else:
        print("'NTP' not in packet")

    # Check if the packet has an HTTP layer
    if 'HTTP' in packet:
        # Access the HTTP layer
        http_layer = packet.http
        print("packet.http:", packet.http)
        # print("dir() function on packet.http:", dir(packet.http))
    else:
        print("'HTTP' not in packet")

    # Check if the packet has an JSON layer
    if 'JSON' in packet:
        # Access the JSON layer
        json_layer = packet.json
        print("packet.json:", packet.json)
        # print("dir() function on packet.json:", dir(packet.json))
    else:
        print("'JSON' not in packet")

    # Check if the packet has an SMB layer
    if 'SMB' in packet:
        # Access the SMB layer
        smb_layer = packet.smb
        print("packet.smb:", packet.smb)
        # print("dir() function on packet.smb:", dir(packet.smb))
    else:
        print("'SMB' not in packet")

    # Check if the packet has an BROWSER layer
    if 'BROWSER' in packet:
        # Access the BROWSER layer
        browser_layer = packet.browser
        print("packet.browser:", packet.browser)
        # print("dir() function on packet.browser:", dir(packet.browser))
    else:
        print("'BROWSER' not in packet")

    # Check if the packet has an NBNS layer
    if 'NBNS' in packet:
        # Access the NBNS layer
        nbns_layer = packet.nbns
        print("NBNS packet:", packet)
        # print("dir() function on packet.nbns:", dir(packet.nbns))
    else:
        print("'NBNS' not in packet")

    # Check if the packet has an IP layer
    if 'IP' in packet:
        # Access the IP layer
        nbns_layer = packet.ip
        print("packet.ip:", packet.ip)
        # print("dir() function on packet.ip:", dir(packet.ip))
    else:
        print("'IP' not in packet")

    # Check if the packet has an DATA layer
    if 'DATA' in packet:
        # Access the DATA layer
        nbns_layer = packet.data
        print("packet.data:", packet.data)
        # print("dir() function on packet.data:", dir(packet.data))
    else:
        print("'DATA' not in packet")

    # Check if the packet has an IGMP layer
    if 'IGMP' in packet:
        # Access the IGMP layer
        igmp_layer = packet.igmp
        print("packet.igmp:", packet.igmp)
        # print("dir() function on packet.igmp:", dir(packet.igmp))
    else:
        print("'IGMP' not in packet")


# Get a list of available network interfaces
available_interfaces = get_available_interfaces()
print("Available network interfaces:", available_interfaces)

if available_interfaces:
    # Specify the network interface to capture traffic from
    network_interface = available_interfaces[2]  # Choose the appropriate interface from the list
    # Capture NetFlow traffic
    capture = pyshark.LiveCapture(interface=network_interface)
    # Set a callback function to process each captured packet
    capture.apply_on_packets(process_packet)
else:
    print("No available network interfaces found.")


"""
dir function details of "packet" class
dir(packet)
['_packet_string', 
'captured_length', 
'eth', 
'frame_info', 
'get_multiple_layers', 
'get_raw_packet', 
'highest_layer', 
'interface_captured', 
'ip', 
'layers', 
'length', 
'number', 
'pretty_print', 
'show', 
'sniff_time', 
'sniff_timestamp', 
'tcp', 
'tls', 
'transport_layer']
"""
"""
dir(packet.tls) - dir function on packet.tls
['_all_fields', 
'_field_prefix', 
'_get_all_field_lines', 
'_get_all_fields_with_alternates', 
'_get_field_or_layer_repr', 
'_get_field_repr', 
'_layer_name', 
'_pretty_print_layer_fields', 
'_sanitize_field_name', 
'app_data', 
'app_data_proto', 
'field_names', 
'get', 
'get_field', 
'get_field_by_showname', 
'get_field_value', 
'has_field', 
'layer_name', 
'pretty_print', 
'raw_mode', 
'record', 
'record_content_type', 
'record_length', 
'record_version']
"""
"""
dir(packet.tcp) - dir function on packet.tcp
['_all_fields', 
'_field_prefix', 
'_get_all_field_lines', 
'_get_all_fields_with_alternates', 
'_get_field_or_layer_repr', 
'_get_field_repr', 
'_layer_name', 
'_pretty_print_layer_fields', 
'_sanitize_field_name', 
'ack', 
'ack_raw', 
'analysis', 
'analysis_bytes_in_flight', 
'analysis_push_bytes_sent', 
'checksum', 
'checksum_status', 
'completeness', 
'completeness_ack', 
'completeness_data', 
'completeness_fin', 
'completeness_rst', 
'completeness_str', 
'completeness_syn', 
'completeness_syn_ack', 
'dstport', 
'field_names', 
'flags', 
'flags_ack', 
'flags_ae', 
'flags_cwr', 
'flags_ece', 
'flags_fin', 
'flags_push', 
'flags_res', 
'flags_reset', 
'flags_str', 
'flags_syn', 
'flags_urg', 
'get', 
'get_field', 
'get_field_by_showname', 
'get_field_value', 
'has_field', 
'hdr_len', 
'layer_name', 
'len', 
'nxtseq', 
'payload', 
'port', 
'pretty_print', 
'raw_mode', 
'seq', 
'seq_raw', 
'srcport', 
'stream', 
'time_delta', 
'time_relative', 
'urgent_pointer', 
'window_size', 
'window_size_scalefactor', 
'window_size_value']
"""

"""
dir(packet.udp) - dir function on packer.udp
['_all_fields', 
'_field_prefix', 
'_get_all_field_lines', 
'_get_all_fields_with_alternates', 
'_get_field_or_layer_repr', 
'_get_field_repr', 
'_layer_name', 
'_pretty_print_layer_fields', 
'_sanitize_field_name', 
'checksum', 
'checksum_status', 
'dstport', 
'field_names', 
'get', 
'get_field', 
'get_field_by_showname', 
'get_field_value', 
'has_field', 
'layer_name', 
'length', 
'payload', 
'port', 
'pretty_print', 
'raw_mode', 
'srcport', 
'stream', 
'time_delta', 
'time_relative']
"""