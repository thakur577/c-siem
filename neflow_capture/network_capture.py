import os
import sys
import pytz
import json
import socket
import psutil
import pyshark
import logging
import binascii
import constants
import configparser
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError

"""
This script streamlines arrange parcel examination by performing a few key errands:


1. Module Consequence:
It imports fundamental modules like 'os', 'sys', 'pytz', 'json', 'socket', 'psutil', 'pyshark', 'binascii', 'configparser', 'logging', and classes from 'datetime' and 'elasticsearch'. These modules give apparatuses for organize communication, information preparing, and logging.

2. Logging Setup:
Arrangement for logging is set up to record nitty gritty data into a record named 'netflow.log'. This guarantees that significant occasions and activities are logged for afterward examination and investigating.

3. Work Definitions:
Two capacities, 'send_json_to_elasticsearch' and 'send_json_to_elasticsearch_alerts', are characterized to send organized JSON information to an Elasticsearch database. They serve as bridges between the parcel handling rationale and the database.

4. Elasticsearch Association Check:
A work, 'check_elasticsearch_connection', confirms network to the Elasticsearch database to handle any association mistakes nimbly.

5. Arrangement Perusing:
The script peruses setup settings from 'netflow.ini' to set up a association to the Elasticsearch database, recover TCP have and harbour settings, and arrange logging parameters.

6. Utility Capacities:
Capacities handle particular errands like preparing hex dumps, checking for uncertain ports, and changing over timestamps between timezones to upgrade usefulness.

7. Interface Recovery:
Another work recovers a list of accessible organize interfacing utilizing 'psutil', permitting the script to connected with the framework and get arrange data powerfully.

8. Bundle Handling:
The 'process_packet' work is the center component, capable for extricating important data from captured organize parcels and sending it to Elasticsearch for capacity and investigation.

9. Client Interaction:
The script prompts the client to choose a organize interface, starts bundle capture utilizing 'pyshark', and forms each captured parcel iteratively. This empowers real-time investigation of organize activity, helping in recognizing security dangers or execution issues.
"""

script_dir = os.path.dirname(os.path.realpath(__file__))
config_file_path = os.path.join(script_dir, constants.ini)

#Function to send packets in (JSON format)to Elasticsearch
def send_json_to_elasticsearch(data):
    try:
        index_name = 'packets'
        if not es_client.indices.exists(index=index_name):
            es_client.indices.create(index=index_name)
        res = es_client.index(index=index_name, body=data)
        logging.info("Data sent to Elasticsearch: %s", res)
    except Exception as e:
        logging.error("Error sending data to Elasticsearch: %s", e)

#Function to send alerts in (JSON format)to Elasticsearch
def send_json_to_elasticsearch_alerts(data):
    try:
        index_name = 'alerts'
        if not es_client.indices.exists(index=index_name):
            es_client.indices.create(index=index_name)
        res = es_client.index(index=index_name, body=data)
        logging.info("Data sent to Elasticsearch: %s", res)
    except Exception as e:
        logging.error("Error sending data to Elasticsearch: %s", e)

#Function to check Elasticsearch connectivity
def check_elasticsearch_connection():
    try:
        es_client.info()
        logging.info("Elasticsearch connection successful.")
    except ConnectionError as e:
        logging.error("Elasticsearch connection error: %s", e)

#To check if the configuration file exists
if os.path.exists(config_file_path):
    # Read configuration settings from the file
    config = configparser.ConfigParser()
    config.read(config_file_path)
    base_dir = config['path']['BASE_DIR']
    ELASTICSEARCH_URL = config['Elasticsearch']['URL']
    ELASTICSEARCH_USERNAME = config['Elasticsearch']['Username']
    ELASTICSEARCH_PASSWORD = config['Elasticsearch']['Password']
    es_client = Elasticsearch([ELASTICSEARCH_URL], basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD), verify_certs=False)
    LOGGING_LEVEL = int(config['logging']['LOGGING_LEVEL'])
    logging.basicConfig(filename=constants.logs, level=LOGGING_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')
    check_elasticsearch_connection()
else:
    logging.error("Configuration file netflow.ini not found.")
    sys.exit(0)

#Function to convert hex dump to ASCII
def hex_dump_to_ascii(hex_dump):
    hex_dump = ''.join(hex_dump.split(':'))
    try:
        byte_data = binascii.unhexlify(hex_dump)
        ascii_text = byte_data.decode('utf-8')
        return ascii_text
    except (binascii.Error, UnicodeDecodeError):
        return "Invalid hex dump"

#Function to check if a port is insecure
def is_insecure_port(port):
    insecure_ports = [21, 22, 23, 25, 80, 110]
    return int(port) in insecure_ports

#Function to convert UTC to IST
def convert_utc_to_ist(utc_timestamp):
    utc_datetime = datetime.utcfromtimestamp(utc_timestamp).replace(microsecond=int((utc_timestamp % 1) * 1e6))
    utc_timezone = pytz.timezone('UTC')
    ist_timezone = pytz.timezone('Asia/Kolkata')
    ist_datetime = utc_datetime.replace(tzinfo=utc_timezone).astimezone(ist_timezone)
    return ist_datetime

#Function to get a list of available network interfaces
def get_available_interfaces():
    try:
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)
    except Exception as e:
        logging.error("Error getting network interfaces: %s", e)
        return []

#Function to process each captured packet
def process_packet(packet):
    logging.info("---------------------------------------------------------------------------------------------------------------------------")
    logging.info("packet.layers: %s", packet.layers)
    logging.info("packet.highest_layer: %s", packet.highest_layer)
    logging.info("packet.pretty_print(): %s", packet.pretty_print())

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
        timestamp = packet.sniff_time

        arp_json = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocol": protocol,
            "timestamp": str(timestamp),
            "arp_op": arp_op,
            "arp_hw_size": arp_hw_size,
            "arp_hw_type": arp_hw_type,
            "arp_proto_size": arp_proto_size,
            "arp_proto_type": arp_proto_type
        }
        send_json_to_elasticsearch(arp_json)

    # Extracting IPv6 packet information
    if hasattr(packet, 'ipv6') and hasattr(packet.ipv6, 'src') and hasattr(packet.ipv6, 'dst'):
        src_ip = packet.ipv6.src
        dst_ip = packet.ipv6.dst
        ipv6_layer = packet['IPv6']
        total_length = int(ipv6_layer.plen)

        if hasattr(packet, 'icmpv6'):
            protocol = "icmpv6"
            timestamp = packet.sniff_time

            if 'ICMPV6' in packet:
                icmpv6_packet = str(packet.icmpv6)

                icmpv6_json = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "timestamp": str(timestamp),
                    "packet_length": total_length,
                    "icmpv6_packet": icmpv6_packet
                }
                send_json_to_elasticsearch(icmpv6_json)

        if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'):
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            protocol_type = "udp"
            timestamp = packet.sniff_time

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
                "timestamp": str(timestamp),
                "packet_length": total_length,
                "dhcpv6_packet": dhcpv6_packet,
                "mdns_packet": mdns_packet,
                "llmnr_packet": llmnr_packet
            }
            send_json_to_elasticsearch(udp_json)

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            protocol_type = "tcp"
            timestamp = packet.sniff_time

            tcp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_type,
                "timestamp": str(timestamp),
                "packet_length": total_length
            }
            send_json_to_elasticsearch(tcp_json)

    # Extracting IPv4 packet information
    if hasattr(packet, 'ip') and hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        ip_layer = packet['IP']
        total_length = int(ip_layer.len)

        if hasattr(packet, 'udp') and hasattr(packet.udp, 'srcport') and hasattr(packet.udp, 'dstport'):
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            protocol_type = "udp"
            timestamp = packet.sniff_time

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
                "timestamp": str(timestamp),
                "packet_length": total_length,
                "ssdp_packet": ssdp_packet,
                "mdns_packet": mdns_packet,
                "dhcp_packet": dhcp_packet,
                "nbns_packet": nbns_packet,
                "smb_packet": smb_packet,
                "dns_packet": dns_packet,
                "llmnr_packet": llmnr_packet
            }
            send_json_to_elasticsearch(udp_json)

            if hasattr(packet.udp, 'payload'):
                netflow_data = packet.udp.payload
                ascii_string = hex_dump_to_ascii(netflow_data)

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            protocol_type = "tcp"
            timestamp = packet.sniff_time

            tcp_json = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_type,
                "timestamp": str(timestamp),
                "packet_length": total_length
            }
            send_json_to_elasticsearch(tcp_json)

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
                    "timestamp": str(timestamp),
                    "packet_length": total_length
                }
                send_json_to_elasticsearch_alerts(insecure_port_alert)

    # Extracting ICMPv6 layer
    if 'ICMPv6' in packet:
        icmpv6_layer = packet.icmpv6
        print("ICMPv6 Type:", icmpv6_layer.type)
        print("ICMPv6 Code:", icmpv6_layer.code)

    # Accessing TLS layer
    if 'TLS' in packet:
        tls_layer = packet.tls

    # Accessing TCP layer
    if 'TCP' in packet:
        tcp_layer = packet.tcp

    # Accessing UDP layer
    if 'UDP' in packet:
        udp_layer = packet.udp

    # Accessing SSDP layer
    if 'SSDP' in packet:
        ssdp_layer = packet.ssdp

    # Accessing SNMP layer
    if 'SNMP' in packet:
        snmp_layer = packet.snmp

    # Accessing ARP layer
    if 'ARP' in packet:
        arp_layer = packet.arp

    # Accessing DNS layer
    if 'DNS' in packet:
        dns_layer = packet.dns

    # Accessing IPv6 layer
    if 'IPv6' in packet:
        ipv6_layer = packet.ipv6

    # Accessing MDNS layer
    if 'MDNS' in packet:
        mdns_layer = packet.mdns

    # Accessing VRRP layer
    if 'VRRP' in packet:
        vrrp_layer = packet.vrrp

    # Accessing STP layer
    if 'STP' in packet:
        stp_layer = packet.stp

    # Accessing LLDP layer
    if 'LLDP' in packet:
        lldp_layer = packet.lldp

    # Accessing DHCP layer
    if 'DHCP' in packet:
        dhcp_layer = packet.dhcp

    # Accessing DHCPV6 layer
    if 'DHCPV6' in packet:
        dhcpv6_layer = packet.dhcpv6

    # Accessing LLMNR layer
    if 'LLMNR' in packet:
        llmnr_layer = packet.llmnr

    # Accessing NTP layer
    if 'NTP' in packet:
        ntp_layer = packet.ntp

    # Accessing HTTP layer
    if 'HTTP' in packet:
        http_layer = packet.http

    # Accessing JSON layer
    if 'JSON' in packet:
        json_layer = packet.json

    # Accessing SMB layer
    if 'SMB' in packet:
        smb_layer = packet.smb

    # Accessing BROWSER layer
    if 'BROWSER' in packet:
        browser_layer = packet.browser

    # Accessing NBNS layer
    if 'NBNS' in packet:
        nbns_layer = packet.nbns

    # Accessing IP layer
    if 'IP' in packet:
        ip_layer = packet.ip

    # Accessing DATA layer
    if 'DATA' in packet:
        data_layer = packet.data

    # Accessing IGMP layer
    if 'IGMP' in packet:
        igmp_layer = packet.igmp


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
    