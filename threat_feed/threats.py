import re
import os
import json
import requests
import logging
import hashlib
import constants
import configparser
from datetime import datetime

ipv4_pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
ipv6_pattern = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

# Set up logging
logger = logging.getLogger(__name__)

# Function to fetch data from a URL, save it to a file, and calculate SHA512 checksum
def fetch_and_save_data(url, directory, filename, config, section):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            logger.info(f"Successfully fetched data from {url}. Status code: {response.status_code}")
            # Create the directory if it doesn't exist
            if not os.path.exists(directory):
                os.makedirs(directory)
            
            # Save the response content to the specified filename
            file_path = os.path.join(directory, filename)
            with open(file_path, 'wb') as file:
                file.write(response.content)
            logger.debug(f"Data from {url} saved to {file_path}")

            # Custom logic for different filenames
            ioc_list = []
            threat_feed_context_details = []

            if filename == constants.dictionary_ssh_attacks:
                for line in response.content.decode("utf-8").splitlines():
                    # Remove comments and strip spaces
                    line = line.strip()
                    threat_feed_context_details.append(line)
                    if line and not line.startswith("#"):  # Check if line is not empty and not a comment
                        ip_address = line.split()[-1]  # Get the last item which is the IP address
                        if re.match(ipv4_pattern, ip_address):  # Check if valid IPv4 address
                            ioc_list.append(ip_address)
                
            elif filename == constants.feodotracker_ip_blocklist:
                for line in response.content.decode("utf-8").splitlines():
                    line = line.strip()
                    threat_feed_context_details.append(line)
                    if line and not line.startswith("\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\""):
                        parts = line.split(",")
                        if parts and len(parts) >= 3:  # Check if parts is not empty after splitting by comma
                            ip = parts[1].strip()  # Extract the IP
                            ip = ip.replace("\"", "")  # Remove the double quotes
                            if re.match(ipv4_pattern, ip):  # Check if valid IPv4 address
                                ioc_list.append(ip)

            elif filename == constants.brute_force_hosts:
                for line in response.content.decode("utf-8").splitlines():
                    line = line.strip()
                    threat_feed_context_details.append(line)
                    if line and not line.startswith("#"):
                        parts = line.split(",")
                        if parts:  # Check if parts is not empty after splitting by comma
                            ipv4 = parts[0].strip()  # Extract the ipv4
                            if ipv4 != "ipv4" and re.match(ipv4_pattern, ipv4):  # Check if valid IPv4 address
                                ioc_list.append(ipv4)

            elif filename == constants.viriback_c2_tracker:
                for line in response.content.decode("utf-8").splitlines():
                    line = line.strip()
                    threat_feed_context_details.append(line)
                    if line and not line.startswith("Family,URL,IP,FirstSeen"):
                        parts = line.split(",")
                        if parts and len(parts) >= 3:  # Check if parts is not empty after splitting by comma
                            url = parts[1].strip()  # Extract the URL
                            ip = parts[2].strip()  # Extract the IP
                            if url != "URL" and ip != "IP" and re.match(ipv4_pattern, ip):
                                ioc_list.append(url)
                                ioc_list.append(ip)

            elif filename == constants.ssl_bl:
                for line in response.content.decode("utf-8").splitlines():
                    line = line.strip()
                    threat_feed_context_details.append(line)
                    if line and not line.startswith("Firstseen,DstIP,DstPort"):
                        parts = line.split(",")
                        if parts and len(parts) >= 3:  # Check if parts is not empty after splitting by comma
                            ip = parts[1].strip()  
                            if ip != "DstIP" and re.match(ipv4_pattern, ip):
                                ioc_list.append(ip)

            elif filename == constants.nocoin:
                domain_regex = r"[a-zA-Z0-9@:%._\+~#?&//=-]{2,256}\.[a-z]{2,20}(?:\.[a-z]{2,20})?\b([-a-zA-Z0-9@:%._\+~#?&//=]*)"
                for line in response.content.decode("utf-8").splitlines():
                    line = line.strip()
                    threat_feed_context_details.append(line)
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) > 1 and parts[0] == "0.0.0.0":
                            domain = parts[-1]  # Extract the domain
                            if re.match(domain_regex, domain):
                                ioc_list.append(domain)

            elif filename in [constants.monero_miner, constants.bbcan177_dnsbl, constants.botvrij_domains, constants.botvrij_hostnames]:
                domain_regex = r"[a-zA-Z0-9@:%._\+~#?&//=-]{2,256}\.[a-z]{2,20}(?:\.[a-z]{2,20})?\b([-a-zA-Z0-9@:%._\+~#?&//=]*)"
                for line in response.content.decode("utf-8").splitlines():
                    line = line.strip()
                    threat_feed_context_details.append(line)
                    if line and not line.startswith("#"):
                        line = line.split("#")[0].strip()  # Remove comments
                        if line and re.match(domain_regex, line):  # Check if line is not empty after removing comments
                            ioc_list.append(line)

            elif filename in [constants.feodotracker_ip_json, constants.cridex_ips]:
                # Load the content of the response as JSON
                ioc_json = json.loads(response.content.decode("utf-8"))
                ioc_list = [ioc_json]
                threat_feed_context_details = [ioc_json]

            elif filename in [constants.talos_ip_blacklist, constants.hancitor_ips, constants.greensnow_blacklist, constants.feodotracker_ip, constants.feodotracker_ip_block, constants.bbcan177_malicious_ips, constants.blocklist_blocklist, constants.brute_force_blocker, constants.alienvault_ip_reputation, constants.ci_badguys, constants.compromised_ips, constants.certin_blacklist]:
                for line in response.content.decode("utf-8").splitlines():
                    # Remove content after # character
                    threat_feed_context_details.append(line)
                    line = line.split("#")[0].strip()
                    if line:  # Check if line is not empty after removing comments
                        if re.match(ipv4_pattern, line):
                            ioc_list.append(line)

            elif filename in [constants.coinblocker_domains, constants.openphish, constants.urlhaus, constants.botvrij_urls]:
                for line in response.content.decode("utf-8").splitlines():
                    # Remove content after # character
                    threat_feed_context_details.append(line)
                    line = line.split("#")[0].strip()
                    if line:  # Check if line is not empty after removing comments
                        ioc_list.append(line)

            
            elif filename == constants.botvrij_ips:
                for line in response.content.decode("utf-8").splitlines():
                    # Remove content after # character
                    threat_feed_context_details.append(line)
                    line = line.split("#")[0].strip().split("|")[0]  # Remove content after "|"
                    if line:  # Check if line is not empty after removing comments and ports
                        if re.match(ipv4_pattern, line):
                            ioc_list.append(line)

            else:
                ioc_list = response.content.decode("utf-8").splitlines()
                threat_feed_context_details = []

            main_data_json = {
                "ioc_list": ioc_list,
                "threat_feed_context_details": threat_feed_context_details
            }

            # Write main data JSON to file
            write_json_to_file(main_data_json, directory, filename)

            # Checksum calculation and verification
            checksum = calculate_checksum(file_path)
            old_checksum = read_checksum(directory, filename)
            if checksum != old_checksum:
                # Write checksum to file
                write_checksum_to_file(checksum, directory, filename)
                # Write metadata JSON to file
                create_json_metadata(directory, filename, config, section)
                logger.info(f"Data for {filename} successfully fetched, saved, and checksum verified.")
            else:
                logger.info(f"No changes detected for {filename}. Data not saved.")

        else:
            logger.error(f"Failed to fetch data from {url}. Status code: {response.status_code}")
    except requests.RequestException as e:
        logger.error(f"An error occurred while fetching data from {url}: {e}")

# Function to calculate SHA512 checksum for a file
def calculate_checksum(file_path):
    hasher = hashlib.sha512()
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

# Function to read old checksum from file
def read_checksum(directory, filename):
    checksum_file_path = os.path.join(directory, f"{filename.split('.')[0]}_checksum.txt")
    old_checksum = ""
    if os.path.exists(checksum_file_path):
        with open(checksum_file_path, 'r') as checksum_file:
            old_checksum = checksum_file.read().strip()
    return old_checksum

# Function to write JSON data to file
def write_json_to_file(data_json, directory, filename):
    main_data_json_file_path = os.path.join(directory, filename)
    with open(main_data_json_file_path, 'w') as main_data_json_file:
        json.dump(data_json, main_data_json_file, indent=4)
    logger.debug(f"Main data JSON file saved: {main_data_json_file_path}")

# Function to write checksum to file
def write_checksum_to_file(checksum, directory, filename):
    checksum_filename = f"{filename.split('.')[0]}_checksum.txt"
    checksum_file_path = os.path.join(directory, checksum_filename)
    with open(checksum_file_path, 'w') as checksum_file:
        checksum_file.write(checksum)
    logger.debug(f"Checksum file saved: {checksum_file_path}")

# Function to create and save JSON metadata file
def create_json_metadata(directory, filename, config, section):
    metadata = {
        "date_time_feed_fetched": str(datetime.now()),
        "threat_feed_url": config[section]['threat_feed_url'],
        "threat_feed_name": config[section]['threat_feed_name'],
        "reference_url": config[section]['reference_url'],
        "description": config[section]['description'],
        "type": config[section]['type'],
        "tags": [] 
    }
    json_file_path = os.path.join(directory, f"{filename.split('.')[0]}_metadata.json")
    with open(json_file_path, 'w') as json_file:
        json.dump(metadata, json_file, indent=4)
    logger.debug(f"Metadata JSON file saved: {json_file_path}")

def main():
    # Path to the configuration file
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_file_path = os.path.join(script_dir, 'threat_feeds_config.ini')

    # Check if the configuration file exists
    if os.path.exists(config_file_path):
        # Read the configuration file
        config = configparser.ConfigParser()
        config.read(config_file_path)

        # Configure logging
        log_file_path = config['paths']['LOG_FILE_PATH']
        logging_level = int(config['logging']['LOGGING_LEVEL'])
        logging_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(filename=log_file_path, level=logging_level, format=logging_format)

        # Fetch and save data from each URL
        for key in config['URLs']:
            url = config['URLs'][key]
            directory_name = key
            filename = f"{directory_name}.json"
            directory_path = os.path.join(config['paths']['BASE_DIR'], directory_name)
            fetch_and_save_data(url, directory_path, filename, config, key)
    else:
        logging.error(f"Configuration file '{config_file_path}' not found.")

if __name__ == "__main__":
    main()
