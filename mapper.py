import subprocess
import re
import math






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
      
    
      
# given a list of networks and their corresponding interfaces, only return the interfaces 
# and networks that are private that will be scanned        
def extract_private(networks, interfaces):
  returned_networks = []
  returned_interfaces = []
  for index in range(len(networks)):
    octets = networks[index].split(".")
    if int(octets[0]) == 10 or (int(octets[0] == 172) and int(octets[1]) == 16) or (int(octets[0] == 192) and int(octets[1]) == 168):

      returned_networks.append(networks[index])
      returned_interfaces.append(interfaces[index])
      
  return returned_networks,returned_interfaces

#get hostname of current device
def get_hostname():
  command = ["hostname"]
  try:
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr = subprocess.PIPE) 
      # extract interfaces and IPs
      output = result.stdout.decode('utf-8')
      name = output.split(".")[0]
      return name
  except Exception as e:
      print(f"An error occurred: {e}")
  
      
 # ip is device ip
 # mask ranges from 24-31 
 # return [first device IP, last device IP] 
 
def get_network_range(ip, mask):
  last_octet = int(ip.split(".")[3])
  square_diff = 32 - int(mask)
  range = 2 ** square_diff 
  first_device = (math.floor(last_octet / range) * range) + 1
  last_device = (math.floor(last_octet / range) * range) + (range - 2)
  return [first_device, last_device]


# get all open ports on the device and their corresponding services and ports
# return the ports and corresponding ports
def extract_ports():
  command = ["ss", "-ntlp"] # ss -ntlp | awk -F ' ' '{print $4,$6}'
  print(command)
  try:
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr = subprocess.PIPE) 
      # extract interfaces and IPs
      
      output = result.stdout.decode('utf-8')
      print(output)
      lines_of_interest = output.split("\n")[1:]
      print(lines_of_interest)
      ports_info = []
      process_info = []
      for line in lines_of_interest:
        
        split_info = line.split(" ")
        print(split_info)
        ports_info.append(split_info[3])
        process_info.append(split_info[5])
      print(ports_info)
      print(process_info)
      ports = []
      processes = []

  
      for index in range(len(ports_info)):
        port_data = ports_info[index]
        process_data = process_info[index]
        ip_port = port_data.split(":")
        if ip_port[0] == "0.0.0.0":
          ports.append(ip_port[1])
          process_split = process_data.split("\"")
          processes.append(process_split[1])
      return ports,processes
      
  except Exception as e:
      print(f"An error occurred: {e}")
  
  

# within the currently SSH'd device, extract all private network information
def extract_device():
  global all_info
  # look for private networks on machine       
  all_networks, all_interfaces = extract_networks()
  networks,interfaces = extract_private(all_networks,all_interfaces)
  hostname = get_hostname()
  device_ips = []
  masks = []
  network_ranges = []
  for network in networks:
    information = network.split("/")
    device_ip = information[0]
    mask = information[1]
    network_range = get_network_range(device_ip,mask)
    
    masks.append(mask)
    device_ips.append(device_ip)
    network_ranges.append(network_range)
    
  ports, processes = extract_ports()
    
  all_info[hostname] = [interfaces,device_ips,masks,network_ranges, ports, processes]

  print(all_info)
  
        
        
      


      
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

# dictionary of all devices and their information
# format: key = hostname, value = [[interfaces], [ips],[masks], [network ranges], [ports], [processes]]  
# network range format: [first device IP, last device IP]
all_info = dict()
extract_device()
      



# scan network

      
      
      

      
  
    

    
  