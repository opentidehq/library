# Script execution on Windows for credential manipulation

## Metadata

- **UUID**: `a566e405-e9db-475f-8447-7875fa127716`
- **Schema**: `threat::1.0`
- **TLP**: clear

## Description
One example of script execution for credential manipulation is the use of a
Python or other type of script to access and read/change a user's credentials
stored in a file, such as Windows Credential Manager. 
The script could be designed to read the file, decrypt the stored
credentials, make changes to the username or password, and then save the
updated information back to the file. Threat actors are using also different
cmd utilities in combination with script commands to gain or modify user's
credentials. For example, such utilities can be cmdkey, keyring libraries
and others.

Example for a script that can manipulate a credentials file:

import os
import json
import base64

# Function to encrypt the credentials
def encrypt_credentials(credentials):
encoded_credentials = base64.b64encode(json.dumps(credentials).encode())
return encoded_credentials.decode()

# Function to decrypt the credentials
def decrypt_credentials(encoded_credentials):
decoded_credentials = json.loads(base64.b64decode(encoded_credentials).decode())
return decoded_credentials

# Function to update the credentials
def update_credentials(username, password):
# Reading the credentials from file
with open("credentials.txt", "r") as file:
    encoded_credentials = file.read()
# Decrypting the credentials
credentials = decrypt_credentials(encoded_credentials)
# Updating the username and password
credentials["username"] = username
credentials["password"] = password
# Encrypting the updated credentials
encoded_credentials = encrypt_credentials(credentials)
# Saving the updated credentials to file
with open("credentials.txt", "w") as file:
    file.write(encoded_credentials)

# Function call to update the credentials
update_credentials("new_username", "new_password")

Example for python code which extracts user's credentials with cmdkey utility:

import os

os.system('cmdkey /add:TERMSRV/X.X.X.X/user:Administrator /pass:<password>')
os.system('mstsc /v:X.X.X.X')
os.system('cmdkey /delete:TERMSRV/X.X.X.X')

Example for keyring library python script for credential manipulation.
Keyring libraries are used to manage the credentials. In the script threat 
actors are using different functions like: set_credentials(),
get_credentials() and update_credentials() to set, retrieve or change
username and password for the specific user or service. Keyring library
uses the operating system's secure storage to store the credentials. 
This secure storage provides credential encryption and the passwords are
not stored in plain text.

import keyring

# Function to set the credentials
def set_credentials(username, password):
keyring.set_password("service_name", username, password)

# Function to get the credentials
def get_credentials():
username = input("Enter your username: ")
password = keyring.get_password("service_name", username)
return username, password

Some credential stealers, for example Ryuk and TrickBot are based on custom
scripts. For example, TrickBot is configured to use network propagation
script modules (sharedll and tabdll) that rely on SMB and can harvest
credentials and propagate to additional systems in the network.

## Techniques
- T1098.001
- T1059.003
- T1555
- T1003
