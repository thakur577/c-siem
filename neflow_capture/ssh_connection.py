import paramiko
import constants

# Create a new SSH client
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Connect to the Ubuntu machine
client.connect('192.168.211.231', username='<username>', password='<password>')

# Run a command (replace 'ls' with the command you want to run)
stdin, stdout, stderr = client.exec_command('ls')

# Print the output of the command
print(stdout.read().decode())

# Close the connection
client.close()
