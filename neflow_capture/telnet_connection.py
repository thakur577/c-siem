import telnetlib
import constants

# Define the host and port
HOST = constants.ip  # IP address of the Ubuntu machine
PORT = 23  # Telnet default port

# Create a Telnet object
tn = telnetlib.Telnet(HOST, PORT)

# Read data from the server
data = tn.read_until(b"\n")  # Read until a newline character is encountered

# Print the received data
print(data.decode('ascii'))

# Close the connection
tn.close()
