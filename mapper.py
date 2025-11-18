import subprocess
import re






# first within pivot, we need to enumerate first private network
# user should be sudo'd into pivot with "sudo su"

def extract_networks():
  command = ["ip", "a"]

  try:
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr = subprocess.PIPE) 
      # extract interfaces and IPs
      output = "\n" + result.stdout.decode('utf-8')
      interfaces_info = re.split(r'[\n][0-9]: ',output)[1:]
  
      interfaces = []
      networks = []
      for info in interfaces_info:
        interface_rest = info.split(": ")

        inet_rest = interface_rest[1].split("inet ")

        if len(inet_rest) > 1:
          interfaces.append(interface_rest[0])
          net_rest = inet_rest[1].split(" ")

          network = net_rest[0]
          networks.append(network)
      return networks,interfaces
  except Exception as e:
      print(f"An error occurred: {e}")
      
    
      
          
def extract_private(networks, interfaces):
  returned_networks = []
  returned_interfaces = []
  for index in range(len(networks)):
    octets = networks[index].split(".")
    print(octets)
    if int(octets[0]) == 10 or (int(octets[0] == 172) and int(octets[1]) == 16) or (int(octets[0] == 192) and int(octets[1]) == 168):
      print("found match")
      returned_networks.append(networks[index])
      returned_interfaces.append(interfaces[index])
      
  return returned_networks,returned_interfaces
      
  
        
 
        
        
      


      
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
      
all_networks, all_interfaces = extract_networks()
print(all_networks)
print(all_interfaces)
networks,interfaces = extract_private(all_networks,all_interfaces)
print(networks)
print(interfaces)
      
      
      
      

      
  
    

    
  