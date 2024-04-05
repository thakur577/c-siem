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

# Function to check if a port is insecure
def is_insecure_port(port):
    insecure_ports = [21, 22, 23, 25, 80, 110]
    return int(port) in insecure_ports

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

#Function to process each captured packet
def process_packet(packet):   
    global closed_ports
    global syn_packets
    
    # Check if the counts exceed the thresholds
    if closed_ports > CLOSED_PORTS_THRESHOLD or syn_packets > SYN_PACKETS_THRESHOLD:
        logging.info("Possible Nmap scan detected!")
        logging.info("Closed ports count: %d, SYN packets count: %d", closed_ports, syn_packets)
        # Create a JSON alert
        alert = {
            "timestamp": format_timestamp(packet.sniff_time),
            "src_ip": packet.ip.src,
            "dst_ip": packet.ip.dst,
            "protocol": "tcp" if 'TCP' in packet else "udp",
            "alert": "Possible Nmap scan detected"
        }
        # Send the alert to Elasticsearch
        send_json_over_tcp(tcp_host, tcp_port, alert)
        # Reset the counters
        closed_ports = 0
        syn_packets = 0
    
    tcp_layer = None  # Initialize tcp_layer variable
    # Extracting TCP layer
    if 'TCP' in packet:
        tcp_layer = packet.tcp
        if packet.tcp.flags == '0x004':
            closed_ports += 1
        elif packet.tcp.flags == '0x002':
            syn_packets += 1
    logging.debug("Closed ports count: %d, SYN packets count: %d", closed_ports, syn_packets)

    # Extracting ICMP packet information
    if hasattr(packet, 'icmp'):
        icmp_layer = packet.icmp
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code
        total_length = packet.length
        protocol = "icmp"
        timestamp = format_timestamp(packet.sniff_time)

        icmp_json = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "protocol": protocol,
            "timestamp": timestamp,
            "packet_length": total_length
        }
        send_json_over_tcp(tcp_host, tcp_port, icmp_json)

    # Extracting ARP packet information
    if hasattr(packet, 'arp'):
        arp_layer = packet['ARP']
        src_ip = arp_layer.src_proto_ipv4
        src_mac = arp_layer.src_hw_mac
        dst_ip = arp_layer.dst_proto_ipv4
        dst_mac = arp_layer.dst_hw_mac
        arp_op = arp_layer.opcode
        arp_hw_size = arp_layer.hw_size
        arp_hw_type = arp_layer.hw_type
        arp_proto_size = arp_layer.proto_size
        arp_proto_type = arp_layer.proto_type
        protocol = "arp"
        timestamp = format_timestamp(packet.sniff_time)

        arp_json = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocol": protocol,
            "timestamp": timestamp,
            "arp_op": arp_op,
            "arp_hw_size": arp_hw_size,
            "arp_hw_type": arp_hw_type,
            "arp_proto_size": arp_proto_size,
            "arp_proto_type": arp_proto_type
        }
        send_json_over_tcp(tcp_host, tcp_port, arp_json)

    # Extracting IPv6 packet information
    if hasattr(packet, 'ipv6') and hasattr(packet.ipv6, 'src') and hasattr(packet.ipv6, 'dst'):
        src_ip = packet.ipv6.src
        dst_ip = packet.ipv6.dst
        ipv6_layer = packet['IPv6']
        total_length = int(ipv6_layer.plen)

        if hasattr(packet, 'icmpv6'):
            protocol = "icmpv6"
            timestamp = format_timestamp(packet.sniff_time)

            if 'ICMPV6' in packet:
                icmpv6_packet = str(packet.icmpv6)

                icmpv6_json = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "timestamp": timestamp,
                    "packet_length": total_length,
                    "icmpv6_packet": icmpv6_packet
                }
                send_json_over_tcp(tcp_host, tcp_port, icmpv6_json)

        if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'):
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
            protocol_type = "udp"
            timestamp = format_timestamp(packet.sniff_time)

            dhcpv6_packet = ""
            mdns_packet = ""
            llmnr_packet = ""

            if 'DHCPV6' in packet:
                dhcpv6_packet = str(packet.dhcpv6)

            if 'MDNS' in packet:
                mdns_packet = str(packet.mdns)

            if 'LLMNR' in packet:
                llmnr_packet = str(packet.llmnr)

            udp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_type,
                "timestamp": timestamp,
                "packet_length": total_length,
                "dhcpv6_packet": dhcpv6_packet,
                "mdns_packet": mdns_packet,
                "llmnr_packet": llmnr_packet
            }
            send_json_over_tcp(tcp_host, tcp_port, udp_json)

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
            protocol_type = "tcp"
            timestamp = format_timestamp(packet.sniff_time)
            flags_value = int(tcp_layer.flags, 16)
            urg = (flags_value & 0x20) >> 5
            ack = (flags_value & 0x10) >> 4
            psh = (flags_value & 0x08) >> 3
            rst = (flags_value & 0x04) >> 2
            syn = (flags_value & 0x02) >> 1
            fin = flags_value & 0x01
            tcp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_type,
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

    # Extracting IPv4 packet information
    if hasattr(packet, 'ip') and hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        ip_layer = packet['IP']
        total_length = int(ip_layer.len)

        if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'):
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
            protocol_type = "udp"
            timestamp = format_timestamp(packet.sniff_time)

            ssdp_packet = ""
            mdns_packet = ""
            dhcp_packet = ""
            nbns_packet = ""
            smb_packet = ""
            dns_packet = ""
            llmnr_packet = ""

            if 'SSDP' in packet:
                ssdp_packet = str(packet.ssdp)

            if 'MDNS' in packet:
                mdns_packet = str(packet.mdns)

            if 'DHCP' in packet:
                dhcp_packet = str(packet.dhcp)

            if 'NBNS' in packet:
                nbns_packet = str(packet.nbns)

            if 'SMB' in packet:
                smb_packet = str(packet.smb)

            if 'DNS' in packet:
                dns_packet = str(packet.dns)

            if 'LLMNR' in packet:
                llmnr_packet = str(packet.llmnr)

            udp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_type,
                "timestamp": timestamp,
                "packet_length": total_length,
                "ssdp_packet": ssdp_packet,
                "mdns_packet": mdns_packet,
                "dhcp_packet": dhcp_packet,
                "nbns_packet": nbns_packet,
                "smb_packet": smb_packet,
                "dns_packet": dns_packet,
                "llmnr_packet": llmnr_packet
            }
            send_json_over_tcp(tcp_host, tcp_port, udp_json)

            if hasattr(packet.udp, 'payload'):
                netflow_data = packet.udp.payload
                ascii_string = hex_dump_to_ascii(netflow_data)

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
            protocol_type = "tcp"
            timestamp = format_timestamp(packet.sniff_time)
            flags_value = int(tcp_layer.flags, 16)
            urg = (flags_value & 0x20) >> 5
            ack = (flags_value & 0x10) >> 4
            psh = (flags_value & 0x08) >> 3
            rst = (flags_value & 0x04) >> 2
            syn = (flags_value & 0x02) >> 1
            fin = flags_value & 0x01
            tcp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_type,
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

            if hasattr(packet.tcp, 'payload'):
                netflow_data = packet.tcp.payload
                ascii_string = hex_dump_to_ascii(netflow_data)

            if is_insecure_port(src_port) or is_insecure_port(dst_port):
                insecure_port_alert = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol_type,
                    "timestamp": timestamp,
                    "packet_length": total_length
                }
                send_json_over_tcp(tcp_host, tcp_port, insecure_port_alert)

    if 'UDP' in packet:
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)
        protocol_type = "udp"
        timestamp = format_timestamp(packet.sniff_time)
        
        udp_json = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol_type,
            "timestamp": timestamp,
            "packet_length": total_length
        }
        send_json_over_tcp(tcp_host, tcp_port, udp_json)

        if is_insecure_port(src_port) or is_insecure_port(dst_port):
            insecure_port_alert = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_type,
                "timestamp": timestamp,
                "packet_length": total_length
            }
            send_json_over_tcp(tcp_host, tcp_port, insecure_port_alert)

    # Accessing SMB layer
    if 'SMB' in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        smb_layer = packet.smb
        total_length = packet.length
        protocol = "smb"
        timestamp = format_timestamp(packet.sniff_time)

        smb_json = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "timestamp": timestamp,
            "packet_length": total_length
        }
        send_json_over_tcp(tcp_host, tcp_port, smb_json)


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