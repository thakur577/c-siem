import os
import zipfile
import configparser

script_dir = os.path.dirname(os.path.realpath(__file__))
config_file_path = os.path.join(script_dir, 'threat_feeds_config.ini')

# Function to exclude certain directories or files from being zipped
def should_exclude(file_path):
    # List of directories or files to exclude from zipping
    excluded_items = ['threat_feeds_config.ini', 'unzip.py', 'zip.py', 'threats.py', 'constants.py', '__pycache__']
    for item in excluded_items:
        if item in file_path:
            return True
    return False

def zip_folders(base_dir, output_zip):
    # Create a zip file object
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Walk through each directory in the base directory
        for root, dirs, files in os.walk(base_dir):
            # Iterate over each file in the current directory
            for file in files:
                # Create the full path to the file
                file_path = os.path.join(root, file)
                # Check if the file should be excluded
                if not should_exclude(file_path):
                    # Add the file to the zip archive
                    zipf.write(file_path, os.path.relpath(file_path, base_dir))

def main():
    config = configparser.ConfigParser()
    config.read(config_file_path)
    # Base directory containing the folders to be zipped
    base_dir = config['paths']['BASE_DIR']
    # Output zip file
    output_zip = "Threat_Feeds.zip"
    # Zip the folders
    zip_folders(base_dir, output_zip)
    print(f"All folders in {base_dir} zipped successfully to {output_zip}")

if __name__ == "__main__":
    main()
