import subprocess
import re




# to be run from the pivot machine 
credentials_file = "credentials.txt"

# store usernames and passwords separately to be used
usernames = []
passwords = []
with open("credentials.txt", "r") as file_obj:
  content = file_obj.read()
  lines = content.split("\n")
  for line in lines:
    credential = line.split(":")
    usernames.append(credential[0])
    try:
      passwords.append(credential[1])
    except: 
      print("Error parsing credentials file")
      

# first within pivot, we need to enumerate first private network
# user should be sudo'd into pivot with "sudo su"

sudo_password = "your_sudo_password"  # Replace with your actual password (use with caution!)
command = ["ip", "a"]

try:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr = subprocess.PIPE) 
    # extract interfaces and IPs
    
    output = "\n" + result.stdout.decode('utf-8')
    #print(output)
  
    interfaces_info = re.split(r'[\n][0-9]: ',output)[1:]
    print(interfaces_info)
    interfaces = []
    networks = []
    for info in interfaces_info:
      interface_rest = info.split(": ")
      print(interface_rest)
      interfaces.append(interface_rest[0])
      
      inet_rest = interface_rest[1].split("inet ")
      print(inet_rest)
      net_rest = inet_rest[1].split(" ")
      print(net_rest)
      network = net_rest[0]
      networks.append(network)
      
    print(networks)
    print(interfaces)
      
      
    

except Exception as e:
    print(f"An error occurred: {e}")
      
      

      
  
    

    
  