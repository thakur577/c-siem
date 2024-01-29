import socket
import configparser

config = configparser.ConfigParser()
config.read('netflow.ini')

# fetch tcp_host and tcp_port properties from netflow.ini file
tcp_host = config['netflow']['tcp_host']
tcp_port = config['netflow']['tcp_port']

def start_server(tcp_host, tcp_port):
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to a specific address and port
    server_address = (tcp_host, int(tcp_port))  # Use an empty string for the host to bind to all available interfaces
    server_socket.bind(server_address)
    # Listen for incoming connections (max 1 connection in the backlog)
    server_socket.listen(1)
    print(f"Server is listening on port 9555...")
    try:
        while True:
            # Wait for a connection
            print("Waiting for a connection...")
            client_socket, client_address = server_socket.accept()
            try:
                print(f"Connection from {client_address}")
                # Receive data from the client
                data = client_socket.recv(1024)
                print("data: ",str(data))
                print(f"utf-8 decoded data: {data.decode('utf-8')}")
                if data:
                    print(f"Received data: {data.decode('utf-8')}")
                    # Send a response back to the client
                    response = "Hello from the server!"
                    client_socket.sendall(response.encode('utf-8'))
            finally:
                # Clean up the connection
                client_socket.close()
    except KeyboardInterrupt:
        print("Server stopped.")
    finally:
        # Clean up the server socket
        server_socket.close()

if __name__ == "__main__":
    start_server(tcp_host,tcp_port)
