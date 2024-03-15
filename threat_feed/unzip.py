import os
import zipfile
import configparser

script_dir = os.path.dirname(os.path.realpath(__file__))
config_file_path = os.path.join(script_dir, 'threat_feeds_config.ini')

def decompress_zip(zip_file_path, destination_directory):
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(destination_directory)
        print(f"Successfully decompressed {zip_file_path} to {destination_directory}.")
        return True
    except zipfile.BadZipFile:
        print(f"The file {zip_file_path} is not a zip file or it is corrupted.")
        return False
    except PermissionError:
        print(f"Permission denied: {destination_directory}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def main():
    config = configparser.ConfigParser()
    config.read(config_file_path)
    # Zip file path
    zip_file_path = "Threat_Feeds.zip"
    # Destination directory to extract the zip file
    destination_directory = config['paths']['UNZIP_DIR']
    # Decompress the zip file
    if os.path.exists(zip_file_path):
        decompress_zip(zip_file_path, destination_directory)
    else:
        print("The specified zip file does not exist.")

if __name__ == "__main__":
    main()
