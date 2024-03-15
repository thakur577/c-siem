import smtplib
import constants

# Define the SMTP server and port
SMTP_SERVER = constants.ip
SMTP_PORT = 25  # Default SMTP port

# Define the sender and receiver
sender = constants.sender
receiver = constants.receiver

# Define the email body
body = 'This is a test email.'

# Create the email
email = f'From: {sender}\nTo: {receiver}\nSubject: Test Email\n\n{body}'

# Create a connection to the SMTP server
server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)

# Send the email
server.sendmail(sender, receiver, email)

# Close the connection
server.quit()
