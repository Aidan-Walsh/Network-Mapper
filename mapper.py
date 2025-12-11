import subprocess
import re
import math
import json
import logging
import time
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed






# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variables for SSH tunneling and cycle detection
ssh_tunnels = {}  # Track active SSH tunnels: {ip: port}
tunnel_counter = 8000  # Starting port for SOCKS proxies
discovered_devices = set()  # Track all discovered device IPs to prevent duplicates
scanned_networks = set()  # Track scanned network ranges to prevent re-scanning
device_network_map = {}  # Track which networks each device belongs to
ssh_access_paths = {}  # Track SSH access paths to prevent cycles
network_topology = {}  # Complete topology with cross-references

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
      macs = []
      for info in interfaces_info:
        interface_rest = info.split(": ")
        ether_rest = interface_rest[1].split("link/ether ")
        
        inet_rest = ether_rest[0].split("inet ")
        if len(ether_rest) > 1:
          inet_rest = ether_rest[1].split("inet ")
        print(ether_rest)
        if len(inet_rest) > 1 and len(ether_rest) > 1:
          interfaces.append(interface_rest[0])
      
          mac = ether_rest[1].split(" ")[0]
          macs.append(mac)
          net_rest = inet_rest[1].split(" ")

          network = net_rest[0]
          networks.append(network)
      return networks,interfaces,macs
  except Exception as e:
      print(f"An error occurred: {e}")
      
    
      
# given a list of networks and their corresponding interfaces, only return the interfaces 
# and networks that are private that will be scanned        
def extract_private(networks, interfaces,macs):
  returned_networks = []
  returned_interfaces = []
  returned_macs = []
  for index in range(len(networks)):
    octets = networks[index].split(".")[0].split("/")[0].split(".")  # Handle CIDR notation
    if len(octets) >= 2:
      first_octet = int(octets[0])
      second_octet = int(octets[1]) if len(octets) > 1 else 0
      
      # RFC 1918 private address ranges
      if (first_octet == 10 or 
          (first_octet == 172 and 16 <= second_octet <= 31) or 
          (first_octet == 192 and second_octet == 168)):
        
        returned_networks.append(networks[index])
        returned_interfaces.append(interfaces[index])
        returned_macs.append(macs[index])
      
  return returned_networks,returned_interfaces,returned_macs

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
  try:
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr = subprocess.PIPE) 
      # ports and processes associated to those ports
      
      output = result.stdout.decode('utf-8')
      lines_of_interest = output.split("\n")[1:]
      ports_info = []
      process_info = []
      for line in lines_of_interest:
        
        split_info = line.split(" ")
        filtered_info = [item for item in split_info if item != ""]
        if len(filtered_info) > 5:
          ports_info.append(filtered_info[3])
          process_info.append(filtered_info[5])

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
# if this device has been scanned before, then return false, else true
def extract_device():
  global all_info
  # look for private networks on machine       
  all_networks, all_interfaces,all_macs = extract_networks()
  networks,interfaces,macs = extract_private(all_networks,all_interfaces,all_macs)
  if "".join(macs) not in all_info:
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
      
    all_info["".join(macs)] = [interfaces,device_ips,macs,masks,network_ranges, ports, processes, hostname]
    print(all_info)
    return True,"".join(macs)
  else:
    return False,""

def attempt_ssh_connection(target_ip, username, password):
    """Test if SSH connection is possible to a target"""
    test_command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 {username}@{target_ip} 'echo connected'"
    
    try:
        result = subprocess.run(test_command, shell=True, capture_output=True, text=True, timeout=15)
        return result.returncode == 0
    except:
        return False

def is_device_already_discovered(ip):
    """Check if device has already been discovered"""
    return ip in discovered_devices

def add_device_to_topology(ip, mac, ports, network, discovery_path, ssh_accessible=False):
    """Add device to global topology with deduplication"""
    global network_topology, discovered_devices, device_network_map
    
    if ip not in network_topology:
        network_topology[ip] = {
            'mac': mac,
            'ports': ports,
            'networks': set(),
            'discovery_paths': set(),
            'ssh_accessible': ssh_accessible,
            'first_seen': discovery_path
        }
        discovered_devices.add(ip)
        logger.info(f"New device discovered: {ip}")
    else:
        # Device already exists - update information
        existing = network_topology[ip]
        
        # Update ports if we found new ones
        if ports:
            existing_port_nums = {p[0] for p in existing['ports']}
            new_port_nums = {p[0] for p in ports}
            if not new_port_nums.issubset(existing_port_nums):
                existing['ports'].extend([p for p in ports if p[0] not in existing_port_nums])
                logger.info(f"Updated ports for {ip}: found {len(ports)} additional ports")
        
        # Update SSH accessibility
        if ssh_accessible and not existing['ssh_accessible']:
            existing['ssh_accessible'] = True
            logger.info(f"Device {ip} now marked as SSH accessible")
    
    # Add network and discovery path
    network_topology[ip]['networks'].add(network)
    network_topology[ip]['discovery_paths'].add(discovery_path)
    
    # Update device-network mapping
    if ip not in device_network_map:
        device_network_map[ip] = set()
    device_network_map[ip].add(network)

def is_network_already_scanned(network_range):
    """Check if this network range has already been scanned"""
    return network_range in scanned_networks

def mark_network_as_scanned(network_range):
    """Mark a network range as scanned"""
    scanned_networks.add(network_range)
    logger.info(f"Network {network_range} marked as scanned")

def should_create_ssh_tunnel(target_ip, current_path):
    """Determine if we should create an SSH tunnel to avoid cycles"""
    global ssh_access_paths
    
    # Don't create tunnel if device is already accessible through a shorter path
    if target_ip in ssh_access_paths:
        existing_path_length = len(ssh_access_paths[target_ip])
        current_path_length = len(current_path) + 1
        
        if existing_path_length <= current_path_length:
            logger.info(f"Skipping SSH tunnel to {target_ip} - already accessible via shorter path")
            return False
    
    # Check for potential cycles
    if target_ip in current_path:
        logger.warning(f"Cycle detected: {target_ip} already in path {current_path}")
        return False
    
    return True

def get_network_identifier(ip, mask):
    """Generate a consistent network identifier for deduplication"""
    octets = ip.split('.')
    if int(mask) >= 24:
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/{mask}"
    elif int(mask) >= 16:
        return f"{octets[0]}.{octets[1]}.0.0/{mask}"
    else:
        return f"{octets[0]}.0.0.0/{mask}"

def create_ssh_tunnel(target_ip, username, password, local_port):
    """Create SSH tunnel with SOCKS proxy using sshpass"""
    global ssh_tunnels
    
    command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -D {local_port} -f -N {username}@{target_ip}"
    
    try:
        logger.info(f"Creating SSH tunnel to {target_ip} on port {local_port}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            ssh_tunnels[target_ip] = local_port
            logger.info(f"SSH tunnel established to {target_ip} on port {local_port}")
            return local_port
        else:
            logger.error(f"Failed to create SSH tunnel to {target_ip}: {result.stderr}")
            return None
            
    except Exception as e:
        logger.error(f"Error creating SSH tunnel to {target_ip}: {e}")
        return None

def scan_through_proxy(target_ip, proxy_port, scan_range=None):
    """Scan network through SOCKS proxy using proxychains"""
    discovered_hosts = []
    
    # Configure proxychains for this specific proxy
    proxychains_conf = f"/tmp/proxychains_{proxy_port}.conf"
    
    with open(proxychains_conf, 'w') as f:
        f.write("""strict_chain\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\nsocks5 127.0.0.1 """ + str(proxy_port) + "\n")
    
    if scan_range:
        # Ping sweep through proxy
        network_base = ".".join(target_ip.split(".")[:3])
        start_range, end_range = scan_range
        
        command = f"proxychains4 -f {proxychains_conf} nmap -sn {network_base}.{start_range}-{end_range}"
        
        try:
            logger.info(f"Scanning network {network_base}.{start_range}-{end_range} through proxy")
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            
            # Parse nmap output for discovered hosts
            found_ips = re.findall(r'Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result.stdout)
            discovered_hosts.extend(found_ips)
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Network scan through proxy timed out for {network_base}")
        except Exception as e:
            logger.error(f"Error scanning network through proxy: {e}")
    
    return discovered_hosts

def scan_host_ports_proxy(target_ip, proxy_port):
    """Scan specific host ports through SOCKS proxy"""
    ports_info = []
    
    proxychains_conf = f"/tmp/proxychains_{proxy_port}.conf"
    command = f"proxychains4 -f {proxychains_conf} nmap -Pn -sS --top-ports 1000 {target_ip}"
    
    try:
        logger.info(f"Port scanning {target_ip} through proxy")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=180)
        
        # Parse nmap output more robustly
        lines = result.stdout.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    if state == 'open':
                        port = port_proto.split('/')[0]
                        ports_info.append((port, service))
        
        # Try to get MAC address if possible
        mac_match = re.search(r'MAC Address: ([0-9A-F:]{17})', result.stdout)
        mac_addr = mac_match.group(1) if mac_match else None
        
        return ports_info, mac_addr
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Port scan timed out for {target_ip}")
        return [], None
    except Exception as e:
        logger.error(f"Error port scanning {target_ip}: {e}")
        return [], None

def scan_host_directly(target_ip):
    """Scan host directly from pivot device"""
    command = f"nmap -Pn -sS --top-ports 100 {target_ip}"
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        
        ports_processes = []
        found_mac = None
        
        lines = result.stdout.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    if state == 'open':
                        port = port_proto.split('/')[0]
                        ports_processes.append((port, service))
            
            elif 'MAC Address:' in line:
                mac_match = re.search(r'MAC Address: ([0-9A-F:]{17})', line)
                if mac_match:
                    found_mac = mac_match.group(1)
        
        return ports_processes, found_mac
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Direct scan timed out for {target_ip}")
        return [], None
    except Exception as e:
        logger.error(f"Error directly scanning {target_ip}: {e}")
        return [], None

# Enhanced scan function with cycle detection and deduplication  
# scan the internal network for devices, and scan their ports
# return dictionary of key = value: source ip = [[found_ips],[found_macs], [(ports,service)]]
def scan_network(joined_macs):
    """Enhanced network scanning with cycle detection and deduplication"""
    global all_info, tunnel_counter, usernames, passwords, discovered_devices, network_topology
    
    ranges = all_info[joined_macs][4]
    ips = all_info[joined_macs][1]
    masks = all_info[joined_macs][3]
    returned_dict = {}
    
    # Scan from pivot device first
    for index in range(len(ips)):
        pivot_ip = ips[index]
        network_range = ranges[index]
        mask = masks[index]
        
        # Generate network identifier for deduplication
        network_id = get_network_identifier(pivot_ip, mask)
        
        # Skip if we've already scanned this network
        if is_network_already_scanned(network_id):
            logger.info(f"Skipping already scanned network {network_id}")
            continue
            
        mark_network_as_scanned(network_id)
        
        first_three_octets = pivot_ip.split(".")[:3]
        first_three_octets = ".".join(first_three_octets)
        
        # Initial network discovery
        command = "./scanner.sh " + first_three_octets + " " + str(network_range[0]) + " " + str(network_range[1])
        discovered_ips = []
        
        try:
            logger.info(f"Scanning network range {first_three_octets}.{network_range[0]}-{network_range[1]}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
            
            found_ips = re.findall(r'\((.*?)\)', result.stdout)
            
            for ip in found_ips:
                if ip != pivot_ip and not is_device_already_discovered(ip):
                    discovered_ips.append(ip)
                    
            logger.info(f"Found {len(discovered_ips)} new devices on network {network_id}")
            returned_dict[pivot_ip] = [discovered_ips, [], []]
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Network scan timed out for {first_three_octets}")
            continue
        except Exception as e:
            logger.error(f"Error scanning network: {e}")
            continue
    
        # Now scan individual hosts and attempt SSH tunneling
        current_path = [pivot_ip]  # Track path to prevent cycles
        
        for discovered_ip in discovered_ips:
            if is_device_already_discovered(discovered_ip):
                logger.info(f"Device {discovered_ip} already processed, skipping")
                continue
                
            logger.info(f"Analyzing device {discovered_ip}")
            
            # First, scan ports on this host from pivot
            ports_info, mac_addr = scan_host_directly(discovered_ip)
            
            # Add device to topology
            add_device_to_topology(
                discovered_ip, mac_addr, ports_info, network_id, 
                f"pivot->{discovered_ip}", 
                ssh_accessible=any(port[0] == '22' for port in ports_info)
            )
            
            # Try to establish SSH connection for deeper scanning
            ssh_success = False
            
            # Check if we should create tunnel (avoid cycles)
            if should_create_ssh_tunnel(discovered_ip, current_path):
                for username, password in zip(usernames, passwords):
                    if attempt_ssh_connection(discovered_ip, username, password):
                        logger.info(f"SSH access successful to {discovered_ip} with {username}")
                        
                        # Create SSH tunnel
                        tunnel_port = tunnel_counter
                        tunnel_counter += 1
                        
                        active_tunnel_port = create_ssh_tunnel(discovered_ip, username, password, tunnel_port)
                        
                        if active_tunnel_port:
                            ssh_success = True
                            
                            # Record this access path
                            ssh_access_paths[discovered_ip] = current_path + [discovered_ip]
                            
                            # Scan networks accessible through this tunnel
                            try:
                                time.sleep(2)  # Give tunnel time to establish
                                
                                # Get network range for this device
                                device_network_range = get_network_range(discovered_ip, mask)
                                deeper_network_id = get_network_identifier(discovered_ip, mask)
                                
                                # Only scan if we haven't scanned this network through this device
                                if not is_network_already_scanned(f"{deeper_network_id}_via_{discovered_ip}"):
                                    mark_network_as_scanned(f"{deeper_network_id}_via_{discovered_ip}")
                                    
                                    deeper_hosts = scan_through_proxy(discovered_ip, active_tunnel_port, device_network_range)
                                    
                                    if deeper_hosts:
                                        logger.info(f"Found {len(deeper_hosts)} additional hosts through {discovered_ip}")
                                        
                                        # Scan ports on newly discovered hosts
                                        for deep_host in deeper_hosts:
                                            if not is_device_already_discovered(deep_host):
                                                deep_ports, deep_mac = scan_host_ports_proxy(deep_host, active_tunnel_port)
                                                
                                                # Add to topology
                                                add_device_to_topology(
                                                    deep_host, deep_mac, deep_ports, deeper_network_id,
                                                    f"pivot->{discovered_ip}->{deep_host}",
                                                    ssh_accessible=any(p[0] == '22' for p in deep_ports)
                                                )
                                                
                                                # Update returned data structure
                                                if discovered_ip not in returned_dict:
                                                    returned_dict[discovered_ip] = [[], [], []]
                                                returned_dict[discovered_ip][0].append(deep_host)
                                                returned_dict[discovered_ip][1].append(deep_mac)
                                                returned_dict[discovered_ip][2].append(deep_ports)
                            
                            except Exception as e:
                                logger.error(f"Error scanning through tunnel to {discovered_ip}: {e}")
                        
                        break  # Stop trying credentials once we have access
            
            # Update main returned data structure
            if pivot_ip not in returned_dict:
                returned_dict[pivot_ip] = [[], [], []]
            
            returned_dict[pivot_ip][0].append(discovered_ip)
            returned_dict[pivot_ip][1].append(mac_addr)
            returned_dict[pivot_ip][2].append(ports_info)
    
    # Log cycle detection results
    if len(network_topology) > 0:
        logger.info(f"Network mapping complete. Discovered {len(network_topology)} unique devices")
        
        # Log devices found on multiple networks (potential cycles)
        multi_network_devices = {ip: data for ip, data in network_topology.items() 
                               if len(data['networks']) > 1}
        
        if multi_network_devices:
            logger.info(f"Found {len(multi_network_devices)} devices on multiple networks:")
            for ip, data in multi_network_devices.items():
                networks = list(data['networks'])
                logger.info(f"  {ip}: {networks}")
    
    return returned_dict      
        
    
      


      
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

# Main execution will be moved to the end of the file



def is_headless():
    """Check if running in a headless environment (no GUI)"""
    import os
    return (not os.environ.get('DISPLAY') and 
            not os.environ.get('WAYLAND_DISPLAY') and 
            not os.environ.get('XDG_SESSION_TYPE'))

def generate_ascii_network_map(device_info, discovered_networks):
    """Generate ASCII art network topology with cycle detection for headless systems"""
    global network_topology
    ascii_map = []
    
    # Try to detect if we can use Unicode box drawing characters
    try:
        # Test Unicode support by trying to encode box drawing chars
        "╔═╗".encode('utf-8')
        use_unicode = True
    except:
        use_unicode = False
    
    if use_unicode:
        ascii_map.append("╔══════════════════════════════════════════════════════════╗")
        ascii_map.append("║                    NETWORK TOPOLOGY MAP                 ║")
        ascii_map.append("╚══════════════════════════════════════════════════════════╝")
    else:
        ascii_map.append("+----------------------------------------------------------+")
        ascii_map.append("|                    NETWORK TOPOLOGY MAP                 |")
        ascii_map.append("+----------------------------------------------------------+")
    ascii_map.append("")
    
    # Get pivot information
    pivot_mac = list(device_info.keys())[0]
    pivot_info = device_info[pivot_mac]
    pivot_name = pivot_info[7]  # hostname
    pivot_ips = pivot_info[1]   # IPs
    pivot_ports = pivot_info[5] # ports
    
    # Display pivot device
    if use_unicode:
        ascii_map.append("┌─ PIVOT DEVICE ────────────────────────────────────────┐")
        ascii_map.append(f"│ 🖥️  {pivot_name:<45} │")
        ascii_map.append(f"│ 📍 IPs: {', '.join(pivot_ips):<40} │")
        ascii_map.append(f"│ 🔓 Open Ports: {len(pivot_ports)} services running{'':<25} │")
        ascii_map.append("└───────────────────────────────────────────────────────┘")
        ascii_map.append("    │")
    else:
        ascii_map.append("+- PIVOT DEVICE -----------------------------------------+")
        ascii_map.append(f"| [P] {pivot_name:<45} |")
        ascii_map.append(f"| IPs: {', '.join(pivot_ips):<43} |")
        ascii_map.append(f"| Open Ports: {len(pivot_ports)} services running{'':<29} |")
        ascii_map.append("+-----------------------------------------------------+")
        ascii_map.append("    |")
    
    # Process each network segment
    for idx, (source_ip, discoveries) in enumerate(discovered_networks.items()):
        found_ips, found_macs, found_ports = discoveries
        network_base = '.'.join(source_ip.split('.')[:3]) + '.x'
        
        # Network segment header
        if use_unicode:
            if idx < len(discovered_networks) - 1:
                ascii_map.append("    ├─ NETWORK SEGMENT ─────────────────────────────────")
            else:
                ascii_map.append("    └─ NETWORK SEGMENT ─────────────────────────────────")
                
            ascii_map.append(f"    │  🌐 Network: {network_base}")
            ascii_map.append(f"    │  📊 Discovered: {len(found_ips)} devices")
            ascii_map.append("    │")
        else:
            if idx < len(discovered_networks) - 1:
                ascii_map.append("    +- NETWORK SEGMENT --------------------------------")
            else:
                ascii_map.append("    \\- NETWORK SEGMENT --------------------------------")
                
            ascii_map.append(f"    |  [N] Network: {network_base}")
            ascii_map.append(f"    |  Discovered: {len(found_ips)} devices")
            ascii_map.append("    |")
        
        # List discovered devices
        for i, ip in enumerate(found_ips):
            mac = found_macs[i] if i < len(found_macs) and found_macs[i] else "Unknown"
            ports = found_ports[i] if i < len(found_ports) else []
            
            is_last_device = (i == len(found_ips) - 1)
            is_last_network = (idx == len(discovered_networks) - 1)
            
            # SSH accessibility check
            ssh_accessible = any(port[0] == '22' for port in ports) if ports else False
            
            if use_unicode:
                # Device connection symbol
                if is_last_device and is_last_network:
                    connector = "    │  └──"
                elif is_last_device:
                    connector = "    │  └──"  
                else:
                    connector = "    │  ├──"
                    
                ssh_icon = "🔑" if ssh_accessible else "🔒"
                ascii_map.append(f"{connector} {ssh_icon} {ip}")
                
                if mac != "Unknown":
                    mac_short = mac[:8] + "..." if len(mac) > 11 else mac
                    prefix = "    │      " if not (is_last_device and is_last_network) else "           "
                    ascii_map.append(f"{prefix}MAC: {mac_short}")
                
                if ports:
                    top_ports = ports[:3]  # Show top 3 ports
                    ports_str = ', '.join([f"{p[0]}({p[1]})" for p in top_ports])
                    if len(ports) > 3:
                        ports_str += f" +{len(ports)-3} more"
                        
                    prefix = "    │      " if not (is_last_device and is_last_network) else "           "
                    ascii_map.append(f"{prefix}Ports: {ports_str}")
                
                ascii_map.append("    │")
            else:
                # ASCII-only version
                if is_last_device and is_last_network:
                    connector = "    |  \\--"
                elif is_last_device:
                    connector = "    |  \\--"  
                else:
                    connector = "    |  +--"
                    
                ssh_indicator = "[SSH]" if ssh_accessible else "[---]"
                ascii_map.append(f"{connector} {ssh_indicator} {ip}")
                
                if mac != "Unknown":
                    mac_short = mac[:8] + "..." if len(mac) > 11 else mac
                    prefix = "    |      " if not (is_last_device and is_last_network) else "           "
                    ascii_map.append(f"{prefix}MAC: {mac_short}")
                
                if ports:
                    top_ports = ports[:3]  # Show top 3 ports
                    ports_str = ', '.join([f"{p[0]}({p[1]})" for p in top_ports])
                    if len(ports) > 3:
                        ports_str += f" +{len(ports)-3} more"
                        
                    prefix = "    |      " if not (is_last_device and is_last_network) else "           "
                    ascii_map.append(f"{prefix}Ports: {ports_str}")
                
                ascii_map.append("    |")
    
    # Add cycle detection information
    if network_topology:
        multi_network_devices = {ip: data for ip, data in network_topology.items() 
                               if len(data['networks']) > 1}
        
        if multi_network_devices:
            ascii_map.append("")
            if use_unicode:
                ascii_map.append("╔═══ CROSS-NETWORK DEVICES (Potential Cycles) ════════════╗")
                for ip, data in multi_network_devices.items():
                    networks = list(data['networks'])
                    ascii_map.append(f"║ 🔄 {ip:<15} Networks: {', '.join(networks):<20} ║")
                ascii_map.append("╚══════════════════════════════════════════════════════════╝")
            else:
                ascii_map.append("+== CROSS-NETWORK DEVICES (Potential Cycles) ============+")
                for ip, data in multi_network_devices.items():
                    networks = list(data['networks'])
                    ascii_map.append(f"| [X] {ip:<15} Networks: {', '.join(networks):<16} |")
                ascii_map.append("+=========================================================+")
    
    # Add legend
    ascii_map.append("")
    if use_unicode:
        ascii_map.append("╔═══ LEGEND ═══════════════════════════════════════════════╗")
        ascii_map.append("║ 🖥️  Pivot Device    🌐 Network Segment                  ║")
        ascii_map.append("║ 🔑 SSH Accessible   🔒 No SSH Access                   ║") 
        ascii_map.append("║ 📍 IP Addresses     🔓 Open Ports                      ║")
        if network_topology and any(len(data['networks']) > 1 for data in network_topology.values()):
            ascii_map.append("║ 🔄 Multi-Network    Shows potential cycles             ║")
        ascii_map.append("╚══════════════════════════════════════════════════════════╝")
    else:
        ascii_map.append("+== LEGEND ===============================================+")
        ascii_map.append("| [P] Pivot Device    [N] Network Segment                |")
        ascii_map.append("| [SSH] SSH Access    [---] No SSH Access                |") 
        ascii_map.append("| Shows IP Addresses, MAC, and Open Ports                |")
        if network_topology and any(len(data['networks']) > 1 for data in network_topology.values()):
            ascii_map.append("| [X] Multi-Network   Shows potential cycles             |")
        ascii_map.append("+=========================================================+")
    
    return '\n'.join(ascii_map)

def generate_network_map(device_info, discovered_networks, output_file="network_topology.png"):
    """Generate network topology visualization - works in both GUI and headless environments"""
    
    # First, always generate ASCII version for console output
    ascii_map = generate_ascii_network_map(device_info, discovered_networks)
    
    # Save ASCII version to file
    with open("network_topology_ascii.txt", 'w', encoding='utf-8') as f:
        f.write(ascii_map)
    logger.info("ASCII network map saved to network_topology_ascii.txt")
    
    # Display ASCII map in console
    print("\n" + ascii_map + "\n")
    
    # Try to generate graphical version only if not headless
    if is_headless():
        logger.info("Headless environment detected - skipping graphical visualization")
        logger.info("ASCII network map displayed above and saved to network_topology_ascii.txt")
        return "network_topology_ascii.txt"
    
    # Attempt graphical visualization
    try:
        import matplotlib
        # Use non-interactive backend for headless compatibility
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as patches
        import networkx as nx
        
        # Create directed graph
        G = nx.DiGraph()
        
        # Color schemes for different node types
        colors = {
            'pivot': '#FF6B6B',         # Red for pivot
            'accessible': '#4ECDC4',    # Teal for SSH accessible
            'discovered': '#45B7D1',    # Blue for discovered only
            'network': '#96CEB4',       # Green for network segments
            'multi_network': '#FFD93D'  # Yellow for multi-network devices (potential cycles)
        }
        
        # Add pivot device as root
        pivot_mac = list(device_info.keys())[0]
        pivot_info = device_info[pivot_mac]
        pivot_name = pivot_info[7]  # hostname
        pivot_ips = pivot_info[1]   # IPs
        
        G.add_node(pivot_name, 
                  type='pivot',
                  ips=pivot_ips,
                  ports=pivot_info[5],  # ports
                  mac=pivot_mac)
        
        # Track nodes and their properties
        node_colors = []
        node_sizes = []
        labels = {}
        
        # Process discovered networks
        network_nodes = {}  # Track network nodes for cross-connections
        
        for source_ip, discoveries in discovered_networks.items():
            found_ips, found_macs, found_ports = discoveries
            
            # Add network segment node
            network_segment = f"Network {'.'.join(source_ip.split('.')[:3])}.x"
            if network_segment not in G.nodes():
                G.add_node(network_segment, type='network')
                G.add_edge(pivot_name, network_segment)
                network_nodes[network_segment] = []
            
            # Add discovered devices
            for i, ip in enumerate(found_ips):
                device_name = f"Device_{ip.replace('.', '_')}"
                mac = found_macs[i] if i < len(found_macs) and found_macs[i] else "Unknown"
                ports = found_ports[i] if i < len(found_ports) else []
                
                # Check if device exists in enhanced topology
                device_type = 'discovered'
                if network_topology and ip in network_topology:
                    topo_data = network_topology[ip]
                    device_type = 'accessible' if topo_data['ssh_accessible'] else 'discovered'
                    
                    # If device is on multiple networks, mark it specially
                    if len(topo_data['networks']) > 1:
                        device_type = 'multi_network'
                else:
                    # Fallback to port-based detection
                    is_ssh_accessible = any(port[0] == '22' for port in ports) if ports else False
                    device_type = 'accessible' if is_ssh_accessible else 'discovered'
                
                if device_name not in G.nodes():
                    G.add_node(device_name,
                              type=device_type,
                              ip=ip,
                              mac=mac,
                              ports=ports)
                
                # Add edge if not already exists
                if not G.has_edge(network_segment, device_name):
                    G.add_edge(network_segment, device_name)
                
                network_nodes[network_segment].append(device_name)
        
        # Add cross-network connections for devices on multiple networks
        if network_topology:
            for ip, topo_data in network_topology.items():
                if len(topo_data['networks']) > 1:
                    device_name = f"Device_{ip.replace('.', '_')}"
                    networks = list(topo_data['networks'])
                    
                    # Create cross-network edges (dashed lines)
                    for i in range(len(networks)):
                        for j in range(i+1, len(networks)):
                            net1 = f"Network {networks[i].split('/')[0].rsplit('.', 1)[0]}.x"
                            net2 = f"Network {networks[j].split('/')[0].rsplit('.', 1)[0]}.x"
                            
                            if net1 in G.nodes() and net2 in G.nodes():
                                # Add a special cross-connection edge
                                G.add_edge(net1, net2, style='dashed', color='red', label='cycle')
        
        # Set up the plot
        plt.figure(figsize=(16, 12))
        
        # Use hierarchical layout
        pos = nx.spring_layout(G, k=3, iterations=50)
        
        # Draw nodes with different colors based on type
        for node in G.nodes():
            node_type = G.nodes[node].get('type', 'discovered')
            color = colors.get(node_type, colors['discovered'])
            
            if node_type == 'pivot':
                size = 1500
                shape = 's'  # square
            elif node_type == 'network':
                size = 1000
                shape = 'D'  # diamond
            elif node_type == 'accessible':
                size = 800
                shape = 'o'  # circle
            elif node_type == 'multi_network':
                size = 900
                shape = '^'  # triangle (stands out for cycles)
            else:
                size = 600
                shape = 'o'
            
            nx.draw_networkx_nodes(G, pos, nodelist=[node], 
                                 node_color=color, node_size=size, 
                                 node_shape=shape, alpha=0.8)
        
        # Draw regular edges
        regular_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('style') != 'dashed']
        cycle_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('style') == 'dashed']
        
        nx.draw_networkx_edges(G, pos, edgelist=regular_edges, edge_color='gray', 
                              arrows=True, arrowsize=20, arrowstyle='->', alpha=0.6)
        
        # Draw cycle edges with different style
        if cycle_edges:
            nx.draw_networkx_edges(G, pos, edgelist=cycle_edges, edge_color='red', 
                                  style='dashed', arrows=True, arrowsize=15, 
                                  arrowstyle='->', alpha=0.8, width=2)
        
        # Create labels with device info
        for node in G.nodes():
            node_data = G.nodes[node]
            if node_data.get('type') == 'pivot':
                labels[node] = f"{node}\\n(PIVOT)\\nPorts: {len(node_data.get('ports', []))}"
            elif node_data.get('type') == 'network':
                labels[node] = node
            else:
                ip = node_data.get('ip', '')
                ports = node_data.get('ports', [])
                port_count = len(ports)
                ssh_indicator = " [SSH]" if any(p[0] == '22' for p in ports) else ""
                labels[node] = f"{ip}{ssh_indicator}\\n{port_count} ports"
        
        nx.draw_networkx_labels(G, pos, labels, font_size=8)
        
        # Create legend
        legend_elements = [
            patches.Patch(color=colors['pivot'], label='Pivot Device'),
            patches.Patch(color=colors['network'], label='Network Segment'),
            patches.Patch(color=colors['accessible'], label='SSH Accessible'),
            patches.Patch(color=colors['discovered'], label='Discovered Device'),
            patches.Patch(color=colors['multi_network'], label='Multi-Network (Cycle)')
        ]
        
        # Add cycle edge legend if cycles exist
        if cycle_edges:
            from matplotlib.lines import Line2D
            legend_elements.append(Line2D([0], [0], color='red', linewidth=2, 
                                        linestyle='--', label='Network Cycle'))
        
        plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(0, 1))
        
        # Add title and formatting
        plt.title("Network Topology Map\\nGenerated by Network Mapper", fontsize=16, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        
        # Save the plot
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        logger.info(f"Network topology map saved as {output_file}")
        
        # Also save detailed device information
        with open("network_details.txt", 'w') as f:
            f.write("NETWORK MAPPING RESULTS\\n")
            f.write("=" * 50 + "\\n\\n")
            
            f.write("PIVOT DEVICE:\\n")
            f.write(f"Hostname: {pivot_name}\\n")
            f.write(f"MAC: {pivot_mac}\\n")
            f.write(f"IPs: {', '.join(pivot_ips)}\\n")
            f.write(f"Open Ports: {', '.join([f'{p[0]}({p[1]})' for p in pivot_info[5]])}\\n\\n")
            
            f.write("DISCOVERED DEVICES:\\n")
            f.write("-" * 30 + "\\n")
            
            for source_ip, discoveries in discovered_networks.items():
                found_ips, found_macs, found_ports = discoveries
                
                for i, ip in enumerate(found_ips):
                    mac = found_macs[i] if i < len(found_macs) and found_macs[i] else "Unknown"
                    ports = found_ports[i] if i < len(found_ports) else []
                    
                    f.write(f"\\nDevice: {ip}\\n")
                    f.write(f"MAC: {mac}\\n")
                    f.write(f"Open Ports: {', '.join([f'{p[0]}({p[1]})' for p in ports]) if ports else 'None detected'}\\n")
                    
                    ssh_access = "Yes" if any(p[0] == '22' for p in ports) else "No"
                    f.write(f"SSH Access: {ssh_access}\\n")
        
        logger.info("Detailed network information saved to network_details.txt")
        
        logger.info(f"Graphical network topology saved as {output_file}")
        return output_file
        
    except ImportError as e:
        logger.warning(f"Graphical visualization dependencies missing: {e}")
        logger.info("Install with: pip3 install networkx matplotlib numpy")
        logger.info("ASCII network map is still available above and in network_topology_ascii.txt")
        return "network_topology_ascii.txt"
    except Exception as e:
        logger.warning(f"Could not generate graphical network map: {e}")
        logger.info("ASCII network map is still available above and in network_topology_ascii.txt")
        return "network_topology_ascii.txt"

'''
Original bash script for reference:
#!/bin/bash
echo "First 3 octets of network address (e.g. 192.168.0): "
read net
echo "Starting host range (e.g. 1): "
read start
echo "Ending host range (e.g. 254): "
read end
echo "TCP ports space-delimited (e.g. 21-23 80): "
read ports
for ((i=$start; i<=$end; i++))
do
    nc -nvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open' &
done
wait
'''
      
# Network visualization will be implemented next
# This will create a graph showing:
# - Pivot device as root node  
# - Connected networks as branches
# - Discovered devices with their open ports
# - SSH tunnel paths for deeper network access

def cleanup_ssh_tunnels():
    """Clean up SSH tunnels and temporary files"""
    logger.info("Cleaning up SSH tunnels...")
    
    # Kill SSH tunnel processes
    try:
        subprocess.run("pkill -f 'ssh.*-D.*-f.*-N'", shell=True, capture_output=True)
    except:
        pass
    
    # Remove temporary proxychains config files
    try:
        subprocess.run("rm -f /tmp/proxychains_*.conf", shell=True, capture_output=True)
    except:
        pass

def save_results_to_json(results, filename="network_scan_results.json"):
    """Save scan results to JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving results: {e}")

# Main execution
if __name__ == "__main__":
    logger.info("Starting network mapping from pivot device")
    
    try:
        success, joined_macs = extract_device()
        
        if success:
            logger.info(f"Successfully extracted device info for {joined_macs}")
            found_devices = scan_network(joined_macs)
            
            # Save results with enhanced topology data
            results = {
                "device_info": all_info,
                "discovered_networks": found_devices,
                "network_topology": {ip: {
                    'mac': data['mac'],
                    'ports': data['ports'],
                    'networks': list(data['networks']),  # Convert sets to lists for JSON
                    'discovery_paths': list(data['discovery_paths']),
                    'ssh_accessible': data['ssh_accessible'],
                    'first_seen': data['first_seen']
                } for ip, data in network_topology.items()},
                "ssh_access_paths": ssh_access_paths,
                "detected_cycles": {ip: list(data['networks']) for ip, data in network_topology.items() 
                                   if len(data['networks']) > 1},
                "scan_timestamp": time.time()
            }
            save_results_to_json(results)
            
            # Generate network topology visualization
            logger.info("Generating network topology map...")
            map_file = generate_network_map(all_info, found_devices)
            
            if map_file:
                logger.info(f"Network topology visualization saved as {map_file}")
            
            logger.info("Network mapping completed successfully")
            print(f"\\n" + "="*60)
            print(f"🎯 NETWORK SCAN COMPLETE!")
            print(f"="*60)
            print(f"📊 Results saved to: network_scan_results.json")
            print(f"📋 Detailed report: network_details.txt")
            
            if map_file == "network_topology_ascii.txt":
                print(f"🗺️  Network map: ASCII format (displayed above)")
                print(f"📄 ASCII map file: network_topology_ascii.txt")
                if is_headless():
                    print(f"💡 Note: Running in headless mode - graphical map not generated")
            else:
                print(f"🗺️  Network map: {map_file}")
                print(f"📄 ASCII map: network_topology_ascii.txt")
            
            print(f"="*60)
            
        else:
            logger.warning("Device already scanned or extraction failed")
            
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error during network mapping: {e}")
    finally:
        cleanup_ssh_tunnels()






      
      
      

      
  
    

    
  