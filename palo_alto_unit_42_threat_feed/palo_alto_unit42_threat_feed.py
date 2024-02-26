"""
 Pseudocode:
 1. Check if the configuration file "palo_alto_unit42_threat_feed.ini" exists and is not empty.
    If not, write an error message to "error.txt" with the current date and time, then exit the program.
 2. Import required libraries/modules:
       - logging: for logging messages to a file
       - requests: for making HTTP requests
       - json: for working with JSON data
       - time: for time-related operations
       - configparser: for reading configuration settings from a file
       - hashlib: for calculating checksums
       - os: for operating system-related functionalities
       - datetime: for working with dates and times
 3. Read configuration settings from "palo_alto_unit42_threat_feed.ini" and extract required parameters.
 4. Configure logging settings, including log file location, logging level, and message format.
 5. Define functions for:
       - fetching JSON data from a specified URL with retry and timeout handling
       - fetching JSON data from multiple URLs specified in a list
       - extracting valid JSON file paths from nested data structures
       - calculating the checksum of a file using SHA-512
       - main function responsible for fetching, processing, and saving Palo Alto Unit 42 threat feed data
 6. Implement the main logic:
       - Fetch main JSON data from the base URL
       - If main JSON data is fetched successfully:
           - Extract paths from the main JSON data
           - Fetch JSON data from all extracted paths
           - If all required JSON data is fetched successfully:
               - Format the fetched JSON data
               - Save the formatted JSON data to a file
               - Log a success message
               - Calculate and save the checksum of the generated JSON file
           - If fetching JSON data fails, log an error message
       - If fetching main JSON data fails, log an error message
 7. Execute the main function if the script is executed directly.

"""
 
import logging  
import requests  
import json  
import time 
import configparser  
import hashlib 
import os 
import datetime  

# Retrieving the directory path of the current script
script_dir = os.path.dirname(os.path.realpath(__file__))

# Checking if the configuration file exists and is not empty
config_file_path = os.path.join(script_dir, 'palo_alto_unit42_threat_feed.ini')
if not os.path.exists(config_file_path) or os.path.getsize(config_file_path) == 0:
    # If the configuration file is missing or empty, log an error message with the current date and time
    error_message = f'Error ({datetime.datetime.now()}): Configuration file "palo_alto_unit42_threat_feed.ini" not found or empty.'
    # Write the error message to a separate file called error.txt
    with open(os.path.join(script_dir, 'error.txt'), 'w') as error_file:
        error_file.write(error_message)
    exit()

# Reading configuration settings from the configuration file
config = configparser.ConfigParser()
config.read(os.path.join(script_dir, 'palo_alto_unit42_threat_feed.ini'))
# Extracting configuration settings
MAX_RETRIES = int(config['DEFAULT']['MAX_RETRIES'])
REQUEST_TIMEOUT = int(config['DEFAULT']['REQUEST_TIMEOUT'])
BASE_URL = config['DEFAULT']['BASE_URL']
RAW_BASE_URL = config['DEFAULT']['RAW_BASE_URL']
LOGGING_LEVEL = config['logging']['LOGGING_LEVEL']

# Configuring logging settings
logging.basicConfig(filename=os.path.join(script_dir, 'palo_alto_unit42_logs.logs'), level=int(LOGGING_LEVEL),
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to fetch JSON data from a specified URL
def fetch_json(url):
    """
    Fetches JSON data from a specified URL, handling retries and timeout exceptions gracefully.
    Args:
        url (str): The URL to fetch JSON data from.
    Returns:
        dict: The fetched JSON data from the URL, or None if the request fails.
    """
    for _ in range(MAX_RETRIES):
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)  # Sending an HTTP GET request to the URL
            response.raise_for_status()  # Raises an exception for error status codes
            return response.json()  # Parsing the JSON data from the response
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logging.error(f"Failed to fetch JSON from {url}: {e}")  # Logging the error message
            time.sleep(1)  # Waiting briefly before retrying
    logging.error(f"Maximum retries exceeded for {url}")  # Logging when maximum retries are exceeded
    return None

# Function to fetch JSON data from all specified paths
def fetch_all_json(base_url, paths):
    """
    Fetches JSON data from all specified paths, handling errors gracefully.
    Args:
        base_url (str): The base URL for the paths.
        paths (list): A list of paths to fetch JSON data from.  
    Returns:
        list: A list of dictionaries containing the fetched JSON data, or None if any fetch fails.
    """
    fetched_data = []
    for path in paths:
        url = f"{RAW_BASE_URL}/{path}"  # Constructing the full URL for fetching JSON data
        data = fetch_json(url)  # Fetching JSON data from the URL
        if data:
            fetched_data.append(data)  # Appending fetched data to the list
        else:
            logging.error(f"Failed to fetch JSON from {url}")  # Logging the failure to fetch JSON data
    return fetched_data or None  # Returning fetched data or None if no data was fetched

# Function to extract valid JSON file paths from the given data structure
def extract_paths(data):
    """
    Extracts valid JSON file paths from the given data structure.
    Args:
        data: The data structure to extract paths from (dict or list).
    Returns:
        list: A list of valid JSON file paths found in the data.
    """
    paths = []
    if isinstance(data, dict):
        paths += [value for key, value in data.items()
                  if key == 'name' and value.endswith('.json')
                  and not (value.startswith('consts') or value.startswith('playbooks'))]
        for value in data.values():
            if isinstance(value, (dict, list)):
                paths += extract_paths(value)
    elif isinstance(data, list):
        for item in data:
            paths += extract_paths(item)
    return paths

def retrieve_existing_checksum(checksum_file_path):
    """
    Retrieves the existing checksum from the checksum file if it exists.
    Args:
        checksum_file_path (str): The path of the checksum file.
    Returns:
        str: The existing checksum read from the file, or None if the file doesn't exist.
    """
    existing_checksum = None
    if os.path.exists(checksum_file_path):
        with open(checksum_file_path, 'r') as checksum_file:
            existing_checksum = checksum_file.read().strip()
    return existing_checksum

def calculate_checksum(file_path, checksum_file_path):
    """
    Calculates the checksum of a file using SHA-512 and updates the checksum file if necessary.
    Args:
        file_path (str): The path of the file to calculate checksum.
        checksum_file_path (str): The path of the checksum file.
    Returns:
        str: The calculated checksum of the file, or an empty string if the calculation fails.
    """
    try:
        existing_checksum = retrieve_existing_checksum(checksum_file_path)
        
        # Calculate checksum of the current file
        with open(file_path, 'rb') as f:
            bytes = f.read()  # Reading entire file as bytes
            calculated_checksum = hashlib.sha512(bytes).hexdigest()  # Calculating SHA-512 checksum
            
            if existing_checksum == calculated_checksum:
                logging.info(f"Checksum already calculated for file: {file_path}. Retrieved checksum: {existing_checksum}")
            else:
                # If the calculated checksum is different from the retrieved checksum, update the checksum file
                with open(checksum_file_path, 'w') as checksum_file:
                    checksum_file.write(calculated_checksum)
                
                logging.info(f"Checksum updated for file: {file_path}. Previous checksum: {existing_checksum}. New checksum: {calculated_checksum}")
            
            return calculated_checksum

    except Exception as e:
        logging.error(f"Error calculating checksum for file: {file_path}. Error: {e}")  # Log error if checksum calculation fails
        return ""


# Main function responsible for fetching, processing, and saving Palo Alto Unit 42 threat feed data
def main():
    """
    Main function responsible for fetching, processing, and saving Palo Alto Unit 42 threat feed data.
    """

    # Fetch main JSON data from the base URL
    main_json = fetch_json(f"{BASE_URL}")

    if main_json:
        # Extract paths from the main JSON data
        paths = extract_paths(main_json)
        
        # Fetch JSON data from all paths
        final_json_data = fetch_all_json(BASE_URL, paths)

        if final_json_data:
            formatted_json = {"palo_alto_unit42_threat_feed": final_json_data}
            filename = "palo_alto_unit42_threat_feed.json"
            file_path = os.path.join(script_dir, filename)
            checksum_file_path = os.path.join(script_dir, 'palo_alto_unit42_threat_feed_checksum.txt')

            # Calculate checksum of the JSON file
            calculated_checksum = calculate_checksum(file_path, checksum_file_path)

            if not os.path.exists(file_path):
                # If JSON file does not exist, write the formatted JSON data to the file
                with open(file_path, "w") as json_file:
                    json.dump(formatted_json, json_file, indent=2)
                    logging.info(f"Palo Alto Unit 42 threat feed data successfully saved to {filename}.")
            else:
                existing_checksum = retrieve_existing_checksum(checksum_file_path)
                if calculated_checksum == existing_checksum:
                    # If the checksum matches, log that the file already exists and has the same checksum
                    logging.info(f"File {filename} already exists and has the same checksum. Not overwriting.")
                else:
                    # If the checksum does not match, update the JSON file and log the update
                    with open(file_path, "w") as json_file:
                        json.dump(formatted_json, json_file, indent=2)
                        logging.info(f"Palo Alto Unit 42 threat feed data updated in {filename}.")

            # Write the calculated checksum to the checksum file
            with open(checksum_file_path, "w") as f:
                f.write(calculated_checksum)

        else:
            # Log an error if fetching JSON data fails
            logging.error("Failed to fetch all required JSON files.")

    else:
        # Log an error if fetching main JSON data fails
        logging.error("Failed to fetch main JSON data.")
    
if __name__ == "__main__":
    main()
