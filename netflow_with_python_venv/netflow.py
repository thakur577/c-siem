import os
import sys
import pytz
import json
import psutil
import socket
import pyshark
import logging
import binascii
import constants
import configparser
from datetime import datetime, timezone

# Global variables
CLOSED_PORTS_THRESHOLD = 1000
SYN_PACKETS_THRESHOLD = 1000
closed_ports = 0
syn_packets = 0
config = None
tcp_layer = None

# Function that reads configurations from netflow.ini
def load_configuration():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_file_path = os.path.join(script_dir, constants.ini)
    if not os.path.exists(config_file_path):
        raise FileNotFoundError("Configuration file netflow.ini not found.")
    config = configparser.ConfigParser()
    config.read(config_file_path)
    return config

# Function for logging file creation
def setup_logging():
    global config
    config = load_configuration()
    logging_level = int(config['logging']['LOGGING_LEVEL'])
    logging.basicConfig(filename=constants.logs, level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')

#Function to convert hex dump to ASCII
def hex_dump_to_ascii(hex_dump):
    hex_dump = ''.join(hex_dump.split(':'))
    try:
        byte_data = binascii.unhexlify(hex_dump)
        ascii_text = byte_data.decode('utf-8')
        return ascii_text
    except (binascii.Error, UnicodeDecodeError):
        return "Invalid hex dump"

# timestamp: India
def convert_utc_to_ist(utc_timestamp):
    utc_datetime = datetime.fromtimestamp(utc_timestamp, tz=pytz.utc)
    ist_timezone = pytz.timezone(constants.zone)
    ist_datetime = utc_datetime.astimezone(ist_timezone)
    return ist_datetime

def format_timestamp(timestamp):
    return timestamp.astimezone(timezone.utc).isoformat()

#Function to get a list of available network interfaces
def get_available_interfaces():
    try:
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)
    except Exception as e:
        logging.error("Error getting network interfaces: %s", e)
        return []

def send_json_over_tcp(host, port, data):
    if data:
        global config
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
              s.connect((host, int(port)))
              filtered_data = filter_data(data, config)
              if filtered_data:
                json_str = json.dumps(filtered_data)
                s.sendall(json_str.encode('utf-8'))
                print(f"JSON data sent to Socket: {host}:{port} : data sent: {json_str}")
        except Exception as e:
          print(f"Error sending JSON data to Socket: {host}:{port} - {e}")
          logging.error(f"Error sending JSON data to Socket: {host}:{port} - {e}")

def filter_data(data, config):
    # Load IPs and ports to skip from the configuration file
    ips_to_skip = config['skip']['ips']
    ports_to_skip = config['skip']['ports']
    # Check if the data contains IPs and ports to skip, and filter them out
    if (data.get("src_ip") == ips_to_skip or data.get("dst_ip") == ips_to_skip) and (data.get("src_port") == int(ports_to_skip) or data.get("dst_port") == int(ports_to_skip)):
        return None# Skip this data
    else:
        return data

def process_packet(packet):

    if hasattr(packet, 'arp'):
        process_arp_packet(packet)

    elif hasattr(packet, 'ipv6') and hasattr(packet.ipv6, 'src') and hasattr(packet.ipv6, 'dst'):
        process_ipv6_packet(packet)

    elif hasattr(packet, 'ip') and hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
        process_ipv4_packet(packet)

#   elif 'SNMP' in packet:
    #   process_snmp_packet(packet)


def process_http_packet(packet):
    
    try:
        http_layer = packet.http
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        url = http_layer.get('http.request_full_uri', '')
    except AttributeError:
        return None
        
    timestamp = format_timestamp(packet.sniff_time)
    http_json = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "url": url,
        "network_protocol": "tcp",
        "application_protocol": "http",
        "timestamp": timestamp
    }
    return http_json
    
def process_snmp_packet(packet): 
    alert = {
        "timestamp": format_timestamp(packet.sniff_time),
        "src_ip": packet.ip.src,
        "dst_ip": packet.ip.dst,
        "network_protocol": "snmp"
    }
    send_json_over_tcp(tcp_host, tcp_port, alert)

def process_tcp_packet(packet, total_length, src_ip, dst_ip):
    global closed_ports, syn_packets, tcp_layer

    if 'TCP' in packet:
        tcp_layer = packet.tcp
        if packet.tcp.flags == '0x004':
            closed_ports += 1
        elif packet.tcp.flags == '0x002':
            syn_packets += 1
    logging.debug("Closed ports count: %d, SYN packets count: %d", closed_ports, syn_packets)

    if closed_ports > CLOSED_PORTS_THRESHOLD or syn_packets > SYN_PACKETS_THRESHOLD:
        handle_threshold_exceeded(packet)
    
    src_port = int(packet.tcp.srcport)
    dst_port = int(packet.tcp.dstport)
    timestamp = format_timestamp(packet.sniff_time)
    flags_value = int(tcp_layer.flags, 16)
    urg = (flags_value & 0x20) >> 5
    ack = (flags_value & 0x10) >> 4
    psh = (flags_value & 0x08) >> 3
    rst = (flags_value & 0x04) >> 2
    syn = (flags_value & 0x02) >> 1
    fin = flags_value & 0x01
    application_protocol = get_application_protocol(dst_port)

    tcp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "network_protocol": "tcp",
                "application_protocol":application_protocol,
                "timestamp": timestamp,
                "packet_length": total_length,
                "tcp_flags": {
                "urg": urg,
                "ack": ack,
                "psh": psh,
                "rst": rst,
                "syn": syn,
                "fin": fin
                }
            }
    send_json_over_tcp(tcp_host, tcp_port, tcp_json)
    
    if 'HTTP' in packet.layers or src_port == 80 or dst_port == 80:
        http_json = process_http_packet(packet)
        send_json_over_tcp(tcp_host, tcp_port, http_json)

    if hasattr(packet.tcp, 'payload'):
        netflow_data = packet.tcp.payload
        ascii_string = hex_dump_to_ascii(netflow_data)

# Function to process ARP packet
def process_arp_packet(packet):
    arp_layer = packet['ARP']
    try:
        src_ip = arp_layer.src_proto_ipv4
        dst_ip = arp_layer.dst_proto_ipv4
    except AttributeError:
        return None
    src_mac = arp_layer.src_hw_mac
    dst_mac = arp_layer.dst_hw_mac
    arp_op = arp_layer.opcode
    arp_hw_size = arp_layer.hw_size
    arp_hw_type = arp_layer.hw_type
    arp_proto_size = arp_layer.proto_size
    arp_proto_type = arp_layer.proto_type
    timestamp = format_timestamp(packet.sniff_time)
    arp_json = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "network_protocol": "arp",
        "timestamp": timestamp,
        "arp_op": arp_op,
        "arp_hw_size": arp_hw_size,
        "arp_hw_type": arp_hw_type,
        "arp_proto_size": arp_proto_size,
        "arp_proto_type": arp_proto_type
    }
    send_json_over_tcp(tcp_host, tcp_port, arp_json)

# Function to process IPv6 packet
def process_ipv6_packet(packet):
    ipv6_layer = packet['IPv6']
    src_ip = packet.ipv6.src
    dst_ip = packet.ipv6.dst
    total_length = int(ipv6_layer.plen)

    if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'):
        process_udp6_packet(packet, src_ip, dst_ip, total_length)

    elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
        flags_value = int(tcp_layer.flags, 16)
        process_tcp6_packet(packet, src_ip, dst_ip, total_length)

    elif hasattr(packet, 'icmpv6'):
        process_icmpv6_packet(packet)

def process_icmpv6_packet(packet):
        src_ip = packet.ipv6.src
        dst_ip = packet.ipv6.dst
        ipv6_layer = packet['IPv6']
        total_length = int(ipv6_layer.plen)
        protocol = "icmpv6"
        timestamp = format_timestamp(packet.sniff_time)

        icmpv6_json = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "timestamp": str(timestamp),
            "packet_length": total_length
        }
        send_json_over_tcp(tcp_host, tcp_port, icmpv6_json)

def process_tcp6_packet(packet, src_ip, dst_ip, total_length):

    global closed_ports, syn_packets, tcp_layer
    # Extracting TCP layer
    if 'TCP' in packet:
        tcp_layer = packet.tcp
        if packet.tcp.flags == '0x004':
            closed_ports += 1
        elif packet.tcp.flags == '0x002':
            syn_packets += 1
    logging.debug("Closed ports count: %d, SYN packets count: %d", closed_ports, syn_packets)

    if closed_ports > CLOSED_PORTS_THRESHOLD or syn_packets > SYN_PACKETS_THRESHOLD:
        handle_threshold_exceeded(packet)

    src_port = int(packet.tcp.srcport)
    dst_port = int(packet.tcp.dstport)
    timestamp = format_timestamp(packet.sniff_time)
    flags_value = int(tcp_layer.flags, 16)
    urg = (flags_value & 0x20) >> 5
    ack = (flags_value & 0x10) >> 4
    psh = (flags_value & 0x08) >> 3
    rst = (flags_value & 0x04) >> 2
    syn = (flags_value & 0x02) >> 1
    fin = flags_value & 0x01
    application_protocol = get_application_protocol(dst_port)

    if 'HTTP' in packet.layers or src_port == 80 or dst_port == 80:
        http_json = process_http_packet(packet)
        send_json_over_tcp(tcp_host, tcp_port, http_json)

    tcp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "network_protocol": "tcp",
                "application_protocol": application_protocol,
                "timestamp": timestamp,
                "packet_length": total_length,
                "tcp_flags": {
                "urg": urg,
                "ack": ack,
                "psh": psh,
                "rst": rst,
                "syn": syn,
                "fin": fin
                }
            }
    send_json_over_tcp(tcp_host, tcp_port, tcp_json)

def get_application_protocol(port):

    protocol_dict = {
        21: 'ftp',
        25: 'smtp',
        23: 'telnet',
        22: 'ssh',
        443: 'https'
    }

    if port in protocol_dict.keys():
        return protocol_dict.get(port)
    else:
        return ""

def process_udp6_packet(packet, src_ip, dst_ip, total_length):
    application_protocol = ""
    application_protocol = str(packet.highest_layer)

    src_port = int(packet.udp.srcport)
    dst_port = int(packet.udp.dstport)
    timestamp = format_timestamp(packet.sniff_time)

    udp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "network_protocol": "udp",
                "timestamp": timestamp,
                "packet_length": total_length,
                "application_protocol": application_protocol.lower()
            }
    send_json_over_tcp(tcp_host, tcp_port, udp_json)
     
# Function to process IPv4 packet
def process_ipv4_packet(packet):
    ip_layer = packet['IP']
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    total_length = int(ip_layer.len)

    if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'):
        process_udp_packet(packet, total_length, src_ip, dst_ip)
    elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
        process_tcp_packet(packet, total_length, src_ip, dst_ip)
    elif hasattr(packet, 'icmp'):
        process_icmp_packet(packet)
    elif 'SMB' in packet:
        process_smb_packet(packet)

# Function to process UDP packet
def process_udp_packet(packet, total_length, src_ip, dst_ip):
    application_protocol = ""
    application_protocol = str(packet.highest_layer)
    src_port = int(packet.udp.srcport)
    dst_port = int(packet.udp.dstport)
    timestamp = format_timestamp(packet.sniff_time)

    udp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "network_protocol": "udp",
                "timestamp": timestamp,
                "packet_length": total_length,
                "application_protocol": application_protocol.lower()
            }
    send_json_over_tcp(tcp_host, tcp_port, udp_json)


# Function to process SMB packet
def process_smb_packet(packet):
    smb_layer = packet.smb
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    total_length = packet.length
    timestamp = format_timestamp(packet.sniff_time)
    smb_json = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "network_protocol": "tcp",
        "application_protocol": "smb",
        "timestamp": timestamp,
        "packet_length": total_length
    }
    send_json_over_tcp(tcp_host, tcp_port, smb_json)

# Function to handle threshold exceeded
def handle_threshold_exceeded(packet):
    global closed_ports, syn_packets
    logging.info("Possible Nmap scan detected!")
    logging.info("Closed ports count: %d, SYN packets count: %d", closed_ports, syn_packets)
    alert = {
        "timestamp": format_timestamp(packet.sniff_time),
        "src_ip": packet.ip.src,
        "dst_ip": packet.ip.dst,
        "network_protocol": "tcp" if 'TCP' in packet else "udp",
        "alert": "Possible Nmap scan detected"
    }
    send_json_over_tcp(tcp_host, tcp_port, alert)
    closed_ports = 0
    syn_packets = 0

# Function to process ICMP packet
def process_icmp_packet(packet):
    icmp_layer = packet.icmp
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    icmp_type = icmp_layer.type
    icmp_code = icmp_layer.code
    total_length = packet.length
    timestamp = format_timestamp(packet.sniff_time)
    icmp_json = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "network_protocol": "icmp",
        "timestamp": timestamp,
        "packet_length": total_length
    }
    send_json_over_tcp(tcp_host, tcp_port, icmp_json)

def main():
        setup_logging()
        config = load_configuration()
        global tcp_host, tcp_port
        tcp_host = config['netflow']['tcp_host']
        tcp_port = config['netflow']['tcp_port']

        # Move this line to here
        available_interfaces = get_available_interfaces()
        # Check if available interfaces exist
        if available_interfaces:
            print("Available network interfaces:", available_interfaces)
            # Ask user to choose a network interface
            selected_interface = input("Enter the number corresponding to the desired network interface: ")
            try:
                selected_interface_index = int(selected_interface)
                if 0 <= selected_interface_index < len(available_interfaces):
                    network_interface = available_interfaces[selected_interface_index]
                    print("Selected network interface:", network_interface)
                    capture = pyshark.LiveCapture(interface=network_interface)
                    capture.apply_on_packets(process_packet)
                else:
                    print("Invalid interface number. Please select a valid number.")
            except ValueError:
                print("Invalid input. Please enter a number.")
        else:
            print("No available network interfaces found.")
    
if __name__ == "__main__":
    main()