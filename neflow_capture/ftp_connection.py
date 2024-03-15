import ftplib
import constants

def simulate_ftp_client():
    # Connect to the FTP server on the machine
        # Replace with the actual IP address that you want to connect using ftp to in constants.py
    ftp = ftplib.FTP(constants.ip) 
    
    # Replace with the actual username and password that you want to connect using ftp to in constants.py 
    ftp.login(constants.username, constants.password)  

    # List directories/files
    ftp.retrlines(constants.list)

    # Change directory to Desktop
    ftp.cwd(constants.dir)

    # List directories/files in Desktop
    ftp.retrlines(constants.list)

    # Quit the FTP session
    ftp.quit()

simulate_ftp_client()
