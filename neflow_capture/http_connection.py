import socket
import constants

def download_file(url, save_path):
    host, path = url.split('/', 3)[2], '/' + url.split('/', 3)[3]
    server_address = (host, 80)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    try:
        client_socket.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        response_headers = b''
        while b'\r\n\r\n' not in response_headers:
            response_headers += client_socket.recv(1024)

        if b'200 OK' not in response_headers:
            print("Error: Failed to download file. Server returned:", response_headers.decode().split('\r\n', 1)[0])
            return

        file_data = b''
        while (chunk := client_socket.recv(1024)):
            file_data += chunk

        with open(save_path, 'wb') as file:
            file.write(file_data)

        print(f"File downloaded successfully: {save_path}")

    finally:
        client_socket.close()

# Example usage change in constants.py:
download_file(constants.url, constants.file)
