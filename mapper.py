import subprocess
import re
import math
import json
import logging
import time
import socket
import threading
import random
import argparse
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed






# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variables for command line options
UDP_SCAN = False  
ARP_SCAN = False  

# Global variables for SSH tunneling and cycle detection
FIXED_SOCKS_PORT = 9050  
ssh_tunnels = {}  
ssh_processes = {}  
ssh_credentials = {}  
ssh_hop_paths = {}  


# Maps device IP to local port that forwards to it: {device_ip: local_port}
local_port_forwards = {}
local_forward_processes = {}  
next_local_port = 10000  


discovered_devices = set()  
recursively_scanned_devices = set()  
scanned_networks = set()  
device_network_map = {}  
ssh_access_paths = {}  # prevent cycles
network_topology = {}  

# first within pivot, we need to enumerate first private network
# user should be sudo'd into pivot with "sudo su"

def extract_networks():
    # Extract network interfaces and their IP addresses
    command = ["ip", "a"]

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) 
        output = result.stdout
        
        interfaces = []
        networks = []
        macs = []
        
        logger.info("Extracting network interfaces...")
        
        
        # Parse each interface block
        interface_blocks = re.split(r'\n(?=\d+:)', output)
        
        for block in interface_blocks:
            if not block.strip():
                continue
                
            lines = block.strip().split('\n')
            if not lines:
                continue
            
            # Extract interface name from first line
            first_line = lines[0]
            interface_match = re.match(r'\d+:\s*([^:@]+)', first_line)
            if not interface_match:
                continue
                
            interface_name = interface_match.group(1).strip()
            
            # Skip loopback and inactive interfaces
            if interface_name == 'lo' or 'DOWN' in first_line:
                continue
            
            # Extract IP addresses and MAC from subsequent lines
            interface_networks = []
            interface_mac = None
            
            for line in lines[1:]:
                # Look for inet addresses
                inet_match = re.search(r'inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/\d+)', line)
                if inet_match:
                    network = inet_match.group(1)
                    interface_networks.append(network)
                   
                
                # Look for MAC address
                mac_match = re.search(r'link/ether\s+([0-9a-f:]{17})', line, re.IGNORECASE)
                if mac_match and not interface_mac:
                    interface_mac = mac_match.group(1)
                    
            
            # Add each network found on this interface
            for network in interface_networks:
                interfaces.append(interface_name)
                networks.append(network)
                macs.append(interface_mac if interface_mac else "unknown")
        
        logger.info(f"Extracted {len(networks)} networks from {len(set(interfaces))} interfaces")

            
        return networks, interfaces, macs
        
    except Exception as e:
        logger.error(f"Error extracting networks: {e}")
        return [], [], []
      
    
      
# given a list of networks and their corresponding interfaces, only return the interfaces 
# and networks that are private that will be scanned        
def extract_private(networks, interfaces, macs):

    returned_networks = []
    returned_interfaces = []
    returned_macs = []
    
    logger.info("Filtering for private networks...")
    
    for index in range(len(networks)):
        network = networks[index]
        interface = interfaces[index]
        mac = macs[index]
        
        try:
            # Split IP from CIDR 
            ip_part = network.split("/")[0]
            octets = ip_part.split(".")
            
            if len(octets) >= 2:
                first_octet = int(octets[0])
                second_octet = int(octets[1])
                
                # private address range
                is_private = (
                    first_octet == 10 or 
                    (first_octet == 172 and 16 <= second_octet <= 31) or 
                    (first_octet == 192 and second_octet == 168)
                )
                
                if is_private:
                    returned_networks.append(network)
                    returned_interfaces.append(interface)
                    returned_macs.append(mac)
                    logger.info(f"Found private network: {network} on interface {interface}")
              
           
                
        except (ValueError, IndexError) as e:
            logger.warning(f"Error parsing network {network}: {e}")
    
    logger.info(f"Found {len(returned_networks)} private networks")
    return returned_networks, returned_interfaces, returned_macs

#get hostname of current device
def get_hostname():
  command = ["hostname"]
  try:
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) 
      # extract interfaces and IPs
      output = result.stdout
      name = output.split(".")[0]
      return name
  except Exception as e:
      print(f"An error occurred: {e}")
  


# calcualte network range for scanning purposes 
def get_network_range(ip, mask):
   
    try:
        mask_int = int(mask)
        if mask_int < 8 or mask_int > 30:
            mask_int = 24
        
        octets = ip.split(".")
        if len(octets) != 4:
            raise ValueError(f"Invalid IP address format: {ip}")
            
        last_octet = int(octets[3])
        
        # Calculate network size and range
        host_bits = 32 - mask_int
        network_size = 2 ** host_bits
        
       
        if mask_int == 24:
            return [1, 254]
        
        # For other subnet sizes, calculate proper range
        network_start = (last_octet // network_size) * network_size
        first_device = network_start + 1
        last_device = network_start + network_size - 2
        
      
        first_device = max(1, min(first_device, 254))
        last_device = max(first_device, min(last_device, 254))
        
        return [first_device, last_device]
        
    except Exception as e:
        logger.error(f"Error calculating network range for {ip}/{mask}: {e}")
        # Fallback to common range
        return [1, 254]


# get all open ports on the device and their corresponding services and ports
# return the ports and corresponding ports
def extract_ports():
  command = ["ss", "-ntlp"] # ss -ntlp | awk -F ' ' '{print $4,$6}'
  try:
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) 
      
      output = result.stdout
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
    
    logger.info("=== STARTING DEVICE EXTRACTION ===")
    
    
    all_networks, all_interfaces, all_macs = extract_networks()

    
    # Filter for private networks
    networks, interfaces, macs = extract_private(all_networks, all_interfaces, all_macs)
    logger.info(f"Private network filtering found {len(networks)} private networks: {networks}")
    
    if not networks:
        logger.error("No private networks found! Check your network configuration.")
        return False, ""

    # IMPORTANT: Use FIRST (lowest) MAC address as stable device identifier
    # Normalize to lowercase and filter out "unknown" MACs
    valid_macs = [mac.lower() for mac in macs if mac != "unknown"]
    if not valid_macs:
        # If no valid MACs, use hostname
        import socket
        hostname = socket.gethostname()
        mac_key = f"host_{hostname.replace('.', '_').lower()}"

    else:
        # Use ONLY the first (lowest) MAC as device identifier
        # This ensures the same device always has the same ID regardless of how many interfaces are visible
        sorted_macs = sorted(valid_macs)
        mac_key = sorted_macs[0]  # Use first MAC only
        logger.debug(f"Created stable device ID from first MAC (out of {len(sorted_macs)}): {mac_key}")

    if mac_key not in all_info:
        hostname = get_hostname()
       
        
        device_ips = []
        masks = []
        network_ranges = []
        
        for i, network in enumerate(networks):
  
            
            try:
                information = network.split("/")
                if len(information) != 2:
                    logger.error(f"Invalid network format: {network}")
                    continue
                    
                device_ip = information[0]
                mask = information[1]
                network_range = get_network_range(device_ip, mask)
                
                masks.append(mask)
                device_ips.append(device_ip)
                network_ranges.append(network_range)
                
            except Exception as e:
                logger.error(f"Error processing network {network}: {e}")
                continue
        
        if not device_ips:
            logger.error("No valid networks to scan!")
            return False, ""
        
        ports, processes = extract_ports()
        
        all_info[mac_key] = [interfaces, device_ips, macs, masks, network_ranges, ports, processes, hostname]
        
        logger.info("=== DEVICE EXTRACTION SUMMARY ===")
        logger.info(f"Device: {hostname}")
        logger.info(f"Networks to scan: {device_ips}")
        logger.info(f"Network ranges: {network_ranges}")
        logger.info(f"Total networks: {len(device_ips)}")
        
        return True, mac_key
    else:
        logger.info("Device already processed")
        return False, ""
    
    
    """
    Create a local port forward to access target_ip through via_ip
        target_ip: IP of the device we want to reach
        target_port: Port on target device (usually 22 for SSH)
        via_ip: IP of intermediate device (or None for direct connection)
        via_username: Username for intermediate device
        via_password: Password for intermediate device
        via_local_port: If via_ip is also forwarded, the local port to reach it (None if direct)

    Returns the local port that forwards to target_ip, or None if failed
    """
def create_local_port_forward(target_ip, target_port, via_ip, via_username, via_password, via_local_port=None):

    global next_local_port, local_port_forwards, local_forward_processes

    # Check if we already have a forward for this device
    if target_ip in local_port_forwards:
        return local_port_forwards[target_ip]

    # Assign a new local port
    local_port = next_local_port
    next_local_port += 1

    # Build the SSH command
    if via_local_port is None:

        ssh_cmd = (
            f"sshpass -p '{via_password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-L {local_port}:{target_ip}:{target_port} "
            f"-N {via_username}@{via_ip}"
        )

    else:
        # Multi-hop: Connect through existing local forward
        ssh_cmd = (
            f"sshpass -p '{via_password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-p {via_local_port} "
            f"-L {local_port}:{target_ip}:{target_port} "
            f"-N {via_username}@localhost"
        )


    # Log the full command with password masked
    masked_cmd = ssh_cmd.replace(via_password, '***PASSWORD***')
    logger.info(f"[SSH COMMAND] Local forward: {masked_cmd}")

    try:
        # Start the SSH tunnel process in the background
        process = subprocess.Popen(
            ssh_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        time.sleep(2)

        # Check if process is still running
        if process.poll() is not None:
            # Process died
            stderr = process.stderr.read()
            logger.error(f"Local port forward failed to establish: {stderr[:200]}")
            return None

        # Store the forward
        local_port_forwards[target_ip] = local_port
        local_forward_processes[target_ip] = process

        logger.info(f"✓ Local port forward established: localhost:{local_port} forwards to {target_ip}:{target_port}")
        return local_port

    except Exception as e:
        logger.error(f"Failed to create local port forward to {target_ip}: {e}")
        return None
# Test if SSH connection is possible to a target (supports multi-hop via local port forwards)
def attempt_ssh_connection(target_ip, username, password, hop_path=None):
    global local_port_forwards, ssh_credentials

    # Determine if we need local port forward (multi-hop) or direct connection
    if hop_path and len(hop_path) > 0:

        logger.info(f"Testing SSH connection to {target_ip} via hop path {hop_path} with user {username}")
        
        # create intermediate forwards if need be
        local_port = ensure_local_forward_chain(target_ip, hop_path)

        if not local_port:
            logger.error(f"Failed to establish forward chain to {target_ip}")
            return False


    
        test_command = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=10 "
            f"-p {local_port} {username}@localhost 'echo connected'"
        )
 
    else:
        # Direct connection
        test_command = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=10 "
            f"{username}@{target_ip} 'echo connected'"
        )


    masked_cmd = test_command.replace(password, '***PASSWORD***')
    logger.info(f"[SSH COMMAND] Connection test: {masked_cmd}")

    try:
        result = subprocess.run(test_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15)
        if result.returncode == 0:
            logger.info(f"SSH connection successful to {target_ip} with {username}")
            return True
        else:
            logger.info(f"SSH connection failed to {target_ip} with {username}: {result.stderr.strip()[:100]}")
            return False
    except Exception as e:
        logger.warning(f"SSH connection exception for {target_ip} with {username}: {e}")
        return False

#Execute a command on a remote device via SSH (supports multi-hop via local forwards) and return the output
def execute_remote_command(target_ip, username, password, command, timeout=30):
    
    global local_port_forwards

    # Check if we have a local port forward for this device (multi-hop)
    if target_ip in local_port_forwards:
        local_port = local_port_forwards[target_ip]

        ssh_command = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=10 "
            f"-p {local_port} {username}@localhost '{command}'"
        )
    else:
        # Direct connection
        ssh_command = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=10 "
            f"{username}@{target_ip} '{command}'"
        )

    # Log the full command with password masked
    masked_cmd = ssh_command.replace(password, '***PASSWORD***')
    logger.debug(f"[SSH COMMAND] Remote execution: {masked_cmd}")

    try:
        result = subprocess.run(ssh_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        if result.returncode == 0:
            return True, result.stdout
        else:
            logger.warning(f"Remote command failed on {target_ip}: {result.stderr}")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        logger.warning(f"Remote command timed out on {target_ip}")
        return False, "Command timed out"
    except Exception as e:
        logger.error(f"Error executing remote command on {target_ip}: {e}")
        return False, str(e)
# Run a fast ping sweep directly on the remote device
def ping_sweep_remote(target_ip, username, password, network_base, start_range, end_range, exclude_ips=None):
    
    if exclude_ips is None:
        exclude_ips = []

    logger.info(f"Running ping sweep on {target_ip} for {network_base}.{start_range}-{end_range}")

    ping_command = f"""
for i in $(seq {start_range} {end_range}); do
    (ping -c 1 -W 1 {network_base}.$i > /dev/null 2>&1 && echo {network_base}.$i) &
done
wait
"""

    success, output = execute_remote_command(target_ip, username, password, ping_command, timeout=120)

    if not success:
        logger.warning(f"Ping sweep failed on {target_ip}")
        return []

    # list of responding IPs
    discovered_ips = []
    for line in output.strip().split('\n'):
        line = line.strip()
        # Check if valid
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
            # Exclude target device and own IPs
            if line != target_ip and line not in exclude_ips:
                discovered_ips.append(line)
                logger.info(f"Found live host via ping: {line}")
            elif line in exclude_ips:
                logger.debug(f"Skipping {line} (device's own IP)")

    logger.info(f"Ping sweep on {target_ip} found {len(discovered_ips)} live hosts (excluded {len(exclude_ips)} own IPs)")
    return discovered_ips

# Extract network information from a remote device
def extract_remote_device_info(target_ip, username, password):
    global all_info

    logger.info(f"=== EXTRACTING REMOTE DEVICE INFO FROM {target_ip} ===")

    # ip a
    success, ip_output = execute_remote_command(target_ip, username, password, "ip a", timeout=15)
    if not success:
        logger.error(f"Failed to get network info from {target_ip}")
        return False, ""

    # hostname
    success, hostname_output = execute_remote_command(target_ip, username, password, "hostname", timeout=10)
    if not success:
        logger.warning(f"Failed to get hostname from {target_ip}")
        hostname = f"remote_{target_ip.replace('.', '_')}"
    else:
        hostname = hostname_output.strip().split(".")[0]

    # ss -ntlp
    success, ss_output = execute_remote_command(target_ip, username, password, "ss -ntlp", timeout=15)
    if not success:
        logger.warning(f"Failed to get port info from {target_ip}")
        ports = []
        processes = []
    else:
        # Parse output
        ports = []
        processes = []
        lines = ss_output.split("\n")[1:] 
        for line in lines:
            split_info = line.split()
            filtered_info = [item for item in split_info if item != ""]
            if len(filtered_info) > 5:
                port_data = filtered_info[3]
                process_data = filtered_info[5]
                ip_port = port_data.split(":")
                if ip_port[0] == "0.0.0.0" or ip_port[0] == "*":
                    ports.append(ip_port[-1])
                    if '"' in process_data:
                        process_split = process_data.split('"')
                        processes.append(process_split[1] if len(process_split) > 1 else "unknown")
                    else:
                        processes.append("unknown")

    # Parse ip a 
    interfaces = []
    networks = []
    macs = []

    interface_blocks = re.split(r'\n(?=\d+:)', ip_output)
    for block in interface_blocks:
        if not block.strip():
            continue

        lines = block.strip().split('\n')
        if not lines:
            continue

        # Extract interface name
        first_line = lines[0]
        interface_match = re.match(r'\d+:\s*([^:@]+)', first_line)
        if not interface_match:
            continue

        interface_name = interface_match.group(1).strip()

        # Skip loopback and inactive interfaces
        if interface_name == 'lo' or 'DOWN' in first_line:
            continue

        # Extract IP addresses and MAC
        interface_networks = []
        interface_mac = None

        for line in lines[1:]:
            # Look for inet addresses
            inet_match = re.search(r'inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/\d+)', line)
            if inet_match:
                network = inet_match.group(1)
                interface_networks.append(network)
           

            # Look for MAC address
            mac_match = re.search(r'link/ether\s+([0-9a-f:]{17})', line, re.IGNORECASE)
            if mac_match and not interface_mac:
                interface_mac = mac_match.group(1)
               

        # Add each network found on this interface
        for network in interface_networks:
            interfaces.append(interface_name)
            networks.append(network)
            macs.append(interface_mac if interface_mac else "unknown")

    logger.info(f"Extracted {len(networks)} networks from remote device {target_ip}")

    # Filter for private networks
    returned_networks = []
    returned_interfaces = []
    returned_macs = []

    for index in range(len(networks)):
        network = networks[index]
        interface = interfaces[index]
        mac = macs[index]

        try:
            ip_part = network.split("/")[0]
            octets = ip_part.split(".")

            if len(octets) >= 2:
                first_octet = int(octets[0])
                second_octet = int(octets[1])

                is_private = (
                    first_octet == 10 or
                    (first_octet == 172 and 16 <= second_octet <= 31) or
                    (first_octet == 192 and second_octet == 168)
                )

                if is_private:
                    returned_networks.append(network)
                    returned_interfaces.append(interface)
                    returned_macs.append(mac)
                    logger.info(f"Found private network: {network} on interface {interface} (remote: {target_ip})")

        except (ValueError, IndexError) as e:
            logger.warning(f"Error parsing network {network}: {e}")

    if not returned_networks:
        logger.warning(f"No private networks found on remote device {target_ip}")
        return False, ""

    # Process the extracted information
    # Use FIRST (lowest) MAC address as stable device identifier
    # Normalize to lowercase 
    valid_macs = [mac.lower() for mac in returned_macs if mac != "unknown"]
    if not valid_macs:
        # If no valid MACs, use target IP as fallback identifier
        mac_key = f"ip_{target_ip.replace('.', '_')}"
    else:
        # Use the first (lowest) MAC as device identifier
        sorted_macs = sorted(valid_macs)
        mac_key = sorted_macs[0]  # Use first MAC only

    if mac_key not in all_info:
        device_ips = []
        masks = []
        network_ranges = []

        for i, network in enumerate(returned_networks):
            try:
                information = network.split("/")
                if len(information) != 2:
                    logger.error(f"Invalid network format: {network}")
                    continue

                device_ip = information[0]
                mask = information[1]
                network_range = get_network_range(device_ip, mask)

                masks.append(mask)
                device_ips.append(device_ip)
                network_ranges.append(network_range)

            except Exception as e:
                logger.error(f"Error processing network {network}: {e}")
                continue

        if not device_ips:
            logger.error(f"No valid networks to scan on remote device {target_ip}!")
            return False, ""

        all_info[mac_key] = [returned_interfaces, device_ips, returned_macs, masks, network_ranges, ports, processes, hostname]

        logger.info(f"=== REMOTE DEVICE EXTRACTION SUMMARY ({target_ip}) ===")
        logger.info(f"Device: {hostname}")
        logger.info(f"Networks to scan: {device_ips}")
        logger.info(f"Network ranges: {network_ranges}")
        logger.info(f"Total networks: {len(device_ips)}")

        return True, mac_key
    else:
        logger.info(f"Remote device {target_ip} already processed")
        return False, ""

def is_device_already_discovered(ip):
    return ip in discovered_devices

def add_device_to_topology(ip, mac, ports, network, discovery_path, ssh_accessible=False):
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
    else:
        # Device already exists 
        existing = network_topology[ip]
        
        
        if ports:
            existing_port_nums = {p[0] for p in existing['ports']}
            new_port_nums = {p[0] for p in ports}
            if not new_port_nums.issubset(existing_port_nums):
                existing['ports'].extend([p for p in ports if p[0] not in existing_port_nums])
                
        # Update SSH accessibility
        if ssh_accessible and not existing['ssh_accessible']:
            existing['ssh_accessible'] = True
    
    network_topology[ip]['networks'].add(network)
    network_topology[ip]['discovery_paths'].add(discovery_path)
    
    # Update device-network mapping
    if ip not in device_network_map:
        device_network_map[ip] = set()
    device_network_map[ip].add(network)

def is_network_already_scanned(network_range):
    return network_range in scanned_networks

def mark_network_as_scanned(network_range):
    scanned_networks.add(network_range)


def should_create_ssh_tunnel(target_ip, current_path):
    global ssh_access_paths

    # device is already accessible through a shorter path
    if target_ip in ssh_access_paths:
        existing_path_length = len(ssh_access_paths[target_ip])
        current_path_length = len(current_path) + 1

        if existing_path_length <= current_path_length:
            return False

    # Check for potential cycles
    if target_ip in current_path:
        return False
    
    return True

def get_network_identifier(ip, mask):
    octets = ip.split('.')
    if int(mask) >= 24:
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/{mask}"
    elif int(mask) >= 16:
        return f"{octets[0]}.{octets[1]}.0.0/{mask}"
    else:
        return f"{octets[0]}.0.0.0/{mask}"

def is_port_available(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
            return True
    except OSError:
        return False

def get_available_port():
    global used_ports
    for port in SOCKS_PORT_CANDIDATES:
        if port not in used_ports and is_port_available(port):
            used_ports.add(port)
            return port
    
    # try random high ports
    for _ in range(50):  # magic number...
        port = random.randint(10000, 65000)
        if port not in used_ports and is_port_available(port):
            used_ports.add(port)
            return port
    
    return None

def test_socks_proxy(port, timeout=10):

    try:
        import socks
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", port)
        s.settimeout(timeout)
        s.connect(("8.8.8.8", 53))  # Google dns 
        s.close()
        return True
    except Exception as e:
        logger.debug(f"Python socks test failed: {e}")
        # Fallback test using curl if socks module not available
        try:
            test_cmd = f"timeout {timeout} curl -x socks5://127.0.0.1:{port} -s http://www.google.com --max-time {timeout}"
   
            result = subprocess.run(test_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout+2)
            if result.returncode == 0:
                return True
            else:
                return False
        except Exception as e2:
            logger.warning(f"✗ SOCKS proxy on port {port} not responding (curl exception: {e2})")
            return False

def build_proxy_command_chain(target_ip):
    global ssh_hop_paths, ssh_credentials

    if target_ip not in ssh_hop_paths or not ssh_hop_paths[target_ip]:
        # Direct 
        return None

    hop_path = ssh_hop_paths[target_ip]

    # Build nested ProxyCommand chain
    # For path [A, B, C] to reach target D:
    # ssh -D port -o ProxyCommand="ssh -W %h:%p -o ProxyCommand='ssh -W %h:%p user@A' user@B" user@C user@D

    proxy_commands = []

    for i, hop_ip in enumerate(hop_path):
        if hop_ip not in ssh_credentials:
            logger.error(f"No credentials found for hop {hop_ip}")
            return None

        hop_user, hop_pass = ssh_credentials[hop_ip]

        if i == 0:
        
            proxy_cmd = f"sshpass -p '{hop_pass}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p {hop_user}@{hop_ip}"
        else:
            # use prev proxy command
            prev_proxy = proxy_commands[i-1]
            proxy_cmd = f"sshpass -p '{hop_pass}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand='{prev_proxy}' -W %h:%p {hop_user}@{hop_ip}"

        proxy_commands.append(proxy_cmd)

 
    return proxy_commands[-1] if proxy_commands else None

def create_ssh_tunnel(target_ip, username, password, preferred_port=None, hop_path=None):

    global ssh_tunnels, ssh_processes, ssh_credentials, ssh_hop_paths, FIXED_SOCKS_PORT

    
    local_port = FIXED_SOCKS_PORT

    # Check tunnel
    if target_ip in ssh_tunnels and target_ip in ssh_processes:
        existing_port = ssh_tunnels[target_ip]
        existing_process = ssh_processes[target_ip]

    
        if existing_process.poll() is None:  

            if test_socks_proxy(existing_port, timeout=3):
                return existing_port


    logger.info(f"Setting up new SSH tunnel to {target_ip} on fixed port {local_port}")

    # Kill any existing tunnel to this target
    if target_ip in ssh_processes:
        try:
            old_process = ssh_processes[target_ip]
            old_process.terminate()
            old_process.wait(timeout=3)
        except:
            try:
                old_process.kill()
            except:
                pass
        del ssh_processes[target_ip]

    # Force kill any existing process using port 9050
    force_kill_port_9050()
    
    # Store credentials for potential multi-hop use
    ssh_credentials[target_ip] = (username, password)
    if hop_path:
        ssh_hop_paths[target_ip] = hop_path

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            # Check if multi hop
            use_local_forward = target_ip in local_port_forwards

            if use_local_forward:
                forward_port = local_port_forwards[target_ip]
           

            # Create SSH tunnel command with aggressive keepalive
            command = [
                'sshpass', '-p', password,
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ExitOnForwardFailure=yes',
                '-o', 'ConnectTimeout=15',
                '-o', 'ServerAliveInterval=10',  # Send keepalive every 10 seconds
                '-o', 'ServerAliveCountMax=3',   # Allow 3 missed keepalives before disconnect
                '-o', 'TCPKeepAlive=yes',        # Enable TCP keepalive
                '-o', 'Compression=yes'          # Enable compression for better performance
            ]

            if use_local_forward:
                command.extend(['-p', str(forward_port)])

            if use_local_forward:

                command.extend([
                    '-D', str(local_port),
                    '-N',  # No remote command
                    f'{username}@localhost'
                ])
            else:
                # Direct connection
                command.extend([
                    '-D', str(local_port),
                    '-N',  # No remote command
                    f'{username}@{target_ip}'
                ])

            command_str = ' '.join(command)
            masked_cmd = command_str.replace(password, '***PASSWORD***')
            logger.info(f"[SSH COMMAND] Dynamic tunnel (-D {local_port}): {masked_cmd}")


            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # establish tunnel
            time.sleep(5)

     
            poll_result = process.poll()
            if poll_result is not None:
     
                stdout, stderr = process.communicate()

                continue

            # Test tunnel
            tunnel_working = False
            for verify_attempt in range(5):  # Try 5 times

                if test_socks_proxy(local_port, timeout=10):
                    tunnel_working = True
                    break
                else:
              
                    time.sleep(2)

            if tunnel_working:
                # Store process reference to keep it alive
                ssh_processes[target_ip] = process
                ssh_tunnels[target_ip] = local_port
                logger.info(f"✓ SSH tunnel established and verified to {target_ip} on port {local_port}")
                return local_port
            else:

                try:
                    process.terminate()
                    process.wait(timeout=5)
                except:
                    try:
                        process.kill()
                    except:
                        pass

        except Exception as e:
            logger.warning(f"Error creating SSH tunnel to {target_ip} on port {local_port}: {e}")

        # Wait before retry
        if attempt < max_attempts - 1:
            time.sleep(2)
            force_kill_port_9050()

    logger.error(f"Failed to create working SSH tunnel to {target_ip} after {max_attempts} attempts")
    return None

def cleanup_port_tunnels(port):
    try:
        subprocess.run(f"pkill -f 'ssh.*-D.*{port}'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)  # Give time for cleanup
    except:
        pass

def force_kill_port_9050():
    try:

        # Method 1: Kill by pattern matching SSH with -D 9050
        subprocess.run("pkill -9 -f 'ssh.*-D.*9050'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Method 2: Find and kill process listening on port 9050
        result = subprocess.run("lsof -ti:9050", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid:
                    subprocess.run(f"kill -9 {pid}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(2) 
        logger.info("Port 9050 cleared and ready")

    except Exception as e:
        logger.warning(f"Error clearing port 9050: {e}")
        # Continue anyway, the port might already be free

def scan_through_proxy(target_ip, proxy_port, scan_range=None):
    discovered_hosts = []
    if not test_socks_proxy(proxy_port, timeout=5):
        logger.error(f"SOCKS proxy on port {proxy_port} is not responding, skipping scan")
        return []
    
    # Configure proxychains 
    proxychains_conf = f"/tmp/proxychains_{proxy_port}.conf"
    proxychains_config = f"""# Proxychains config for port {proxy_port}
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
localnet 10.0.0.0/255.0.0.0
localnet 172.16.0.0/255.240.0.0
localnet 192.168.0.0/255.255.0.0

[ProxyList]
socks5 127.0.0.1 {proxy_port}
"""

    with open(proxychains_conf, 'w') as f:
        f.write(proxychains_config)
    
    if scan_range:
        # TCP connect scan through proxy 
        network_base = ".".join(target_ip.split(".")[:3])
        start_range, end_range = scan_range

        command = f"proxychains4 -f {proxychains_conf} nmap -sT -Pn -p 22,80,443,445,3389,8080 --open {network_base}.{start_range}-{end_range}"

        try:
            logger.info(f"[PROXYCHAINS COMMAND] Network scan: {command}")
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=600)

            # parse output
            found_ips = re.findall(r'Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result.stdout)

 
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    pass  

            discovered_hosts.extend(found_ips)
            logger.info(f"Found {len(found_ips)} hosts with open ports through proxy")

        except subprocess.TimeoutExpired:
            logger.warning(f"Network scan through proxy timed out for {network_base}")
        except Exception as e:
            logger.error(f"Error scanning network through proxy: {e}")
    
    return discovered_hosts

# returns local port that forwards to target_ip
def ensure_local_forward_chain(target_ip, hop_path):

    global local_port_forwards, ssh_credentials

    # already has forward
    if target_ip in local_port_forwards:
        return local_port_forwards[target_ip]


    if not hop_path or len(hop_path) == 0:
    
        return None

    logger.info(f"Creating local forward chain for {target_ip} through path: {hop_path}")

    # Start from index 1 since hop_path[0] (first hop/pivot) is always directly accessible and needs no forward
    for i in range(1, len(hop_path)):
        hop_ip = hop_path[i]
        if hop_ip not in local_port_forwards:
            # This hop needs a forward through the previous hops
            logger.info(f"Creating intermediate forward for {hop_ip} (hop {i+1}/{len(hop_path)})")

            if hop_ip not in ssh_credentials:
                logger.error(f"No credentials found for intermediate hop {hop_ip}")
                return None

            
            via_ip = hop_path[i-1]

            # get credentials
            if via_ip not in ssh_credentials:
                logger.error(f"No credentials found for via device {via_ip}")
                return None

            via_username, via_password = ssh_credentials[via_ip]

          
            via_local_port = local_port_forwards.get(via_ip, None)

            # Create forward to this intermediate hop
            forward_port = create_local_port_forward(
                target_ip=hop_ip,
                target_port=22,
                via_ip=via_ip,
                via_username=via_username,
                via_password=via_password,
                via_local_port=via_local_port
            )

            if not forward_port:
                logger.error(f"Failed to create intermediate forward for {hop_ip}")
                return None


    # Now create the forward to the target
    via_ip = hop_path[-1]  # SSH through the last hop

    if via_ip == hop_path[0] and len(hop_path) == 1:
        # No local forward needed 
        return None


    if via_ip not in ssh_credentials:
        return None

    via_username, via_password = ssh_credentials[via_ip]
    via_local_port = local_port_forwards.get(via_ip, None)

    logger.info(f"Creating final forward to {target_ip} through {via_ip}")
    local_port = create_local_port_forward(
        target_ip=target_ip,
        target_port=22,
        via_ip=via_ip,
        via_username=via_username,
        via_password=via_password,
        via_local_port=via_local_port
    )

    if local_port:
        return local_port
    else:
        logger.error(f"Failed to create forward to {target_ip}")
        return None

def recreate_ssh_tunnel_for_device(device_ip):
    global ssh_credentials, ssh_hop_paths, ssh_tunnels, ssh_processes

    # Check if we have credentials for this device
    if device_ip not in ssh_credentials:
        return None

    username, password = ssh_credentials[device_ip]
    hop_path = ssh_hop_paths.get(device_ip, [])
    if device_ip in ssh_processes:
        try:
            old_process = ssh_processes[device_ip]
            old_process.terminate()
            old_process.wait(timeout=3)
        except:
            try:
                old_process.kill()
            except:
                pass
        del ssh_processes[device_ip]
        if device_ip in ssh_tunnels:
            del ssh_tunnels[device_ip]

    force_kill_port_9050()

    # Recreate the tunnel
    tunnel_port = create_ssh_tunnel(device_ip, username, password, hop_path=hop_path)

    if tunnel_port:
        return tunnel_port
    else:
        return None

def scan_host_ports_proxy(target_ip, proxy_port, tunnel_device_ip=None, max_retries=2):

    # Outer retry loop
    for retry_attempt in range(max_retries):
        ports_info = []

        # Test proxy before scanning
        if not test_socks_proxy(proxy_port, timeout=5):
            if tunnel_device_ip and retry_attempt < max_retries - 1:
                new_port = recreate_ssh_tunnel_for_device(tunnel_device_ip)
                if new_port:
                    proxy_port = new_port
                    time.sleep(2)  
                    continue
            return [], None

        proxychains_conf = f"/tmp/proxychains_{proxy_port}.conf"

        # -sT (TCP connect) works with proxychains 
        scan_commands = [
            f"timeout -k 2 10 proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 1000 {target_ip}",
            f"timeout -k 2 10 proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 500 {target_ip}",  # Fallback with fewer ports
            f"timeout -k 2 10 proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 100 {target_ip}"   # Smaller port range fallback
        ]

        # Try each scan command until one succeeds
        scan_succeeded = False
        for i, command in enumerate(scan_commands):
            try:
                scan_type = ["TCP connect (1000 ports)", "TCP connect (500 ports)", "TCP connect (100 ports)"][i]
                logger.info(f"[PROXYCHAINS COMMAND] Port scan: {command}")

                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          universal_newlines=True, preexec_fn=os.setsid)

                try:
                    stdout, stderr = process.communicate(timeout=12)  
                    result = type('obj', (object,), {'returncode': process.returncode, 'stdout': stdout, 'stderr': stderr})()
                except subprocess.TimeoutExpired:
        
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except:
                        pass
                    process.kill()
                    process.wait()


                    if i == len(scan_commands) - 1 and tunnel_device_ip and retry_attempt < max_retries - 1:
                        break  # Break to outer retry loop

                    if i == len(scan_commands) - 1:
                        return [], None
                    continue

                # Exit code 124 means timeout command killed the process
                if result.returncode == 124:

                    if i == len(scan_commands) - 1 and tunnel_device_ip and retry_attempt < max_retries - 1:
                        break 

                    if i == len(scan_commands) - 1:
                        return [], None
                    continue

                if result.returncode == 0 and result.stdout:
                    # Parse nmap output 
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

                    if ports_info or i == len(scan_commands) - 1:  # Return results if found or last attempt
    
                        return ports_info, mac_addr
                else:
                    logger.warning(f"Scan attempt {i+1} failed for {target_ip}: {result.stderr}")
            except subprocess.TimeoutExpired:
                if i == len(scan_commands) - 1 and tunnel_device_ip and retry_attempt < max_retries - 1:
                    break  # Break to outer retry loop
                if i == len(scan_commands) - 1:
                    return [], None
            except Exception as e:
                if i == len(scan_commands) - 1:
                    return [], None

        # If we got here, no scan succeeded
        if tunnel_device_ip and retry_attempt < max_retries - 1:
    
            new_port = recreate_ssh_tunnel_for_device(tunnel_device_ip)
            if new_port:
                proxy_port = new_port
                time.sleep(2)
                continue  # Retry 

    return [], None

def discover_network_devices(network_base, start_range, end_range, pivot_ip):

    discovered_ips = []

    # Method 1: ARP table scan (fastest for local network) - only if ARP_SCAN is enabled
    if ARP_SCAN:
        logger.info(f"Scanning network {network_base}.{start_range}-{end_range} using ARP table")
        try:
            arp_result = subprocess.run("arp -a", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
            arp_ips = re.findall(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', arp_result.stdout)

            for ip in arp_ips:
                octets = ip.split('.')
                if (octets[0] + '.' + octets[1] + '.' + octets[2]) == network_base:
                    last_octet = int(octets[3])
                    if start_range <= last_octet <= end_range and ip != pivot_ip:
                        discovered_ips.append(ip)
                        logger.info(f"Found device via ARP: {ip}")

        except Exception as e:
            logger.warning(f"ARP scan failed: {e}")
    else:
        logger.debug(f"ARP scanning disabled (use -arp to enable)")
    
    # Method 2: Enhanced nmap ping sweep
    network_cidr = f"{network_base}.{start_range}"
    if end_range == 254:
        network_cidr = f"{network_base}.0/24"
    else:
        # Calculate CIDR for custom range
        range_size = end_range - start_range + 1
        cidr_bits = 32 - math.ceil(math.log2(range_size))
        network_cidr = f"{network_base}.{start_range}/{cidr_bits}"
    
    logger.info(f"Performing enhanced ping sweep on {network_cidr}")
    
    # Multiple nmap discovery techniques
    discovery_commands = [
        f"nmap -sn -PE -PP -PM --max-retries=2 --min-parallelism=100 {network_cidr}",  # ICMP ping sweep
        f"nmap -sn -PS22,80,443 --max-retries=2 {network_cidr}",  # TCP SYN ping to common ports
        f"nmap -sn -PA80,443 --max-retries=2 {network_cidr}",     # TCP ACK ping
    ]

    # Add UDP ping only if UDP_SCAN is enabled (it's time-consuming)
    if UDP_SCAN:
        discovery_commands.append(f"nmap -sn -PU53,67,68,161 --max-retries=1 {network_cidr}")  # UDP ping to common ports

    scan_types = ["ICMP ping", "TCP SYN ping", "TCP ACK ping"]
    if UDP_SCAN:
        scan_types.append("UDP ping")
    
    for i, command in enumerate(discovery_commands):
        try:
            scan_type = scan_types[i]
            if scan_type == "UDP ping":
                logger.info(f"Running {scan_type} sweep (UDP scan enabled)...")
            else:
                logger.info(f"Running {scan_type} sweep...")
            
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
            
            if result.returncode == 0:
                # Extract IPs from nmap output
                nmap_ips = re.findall(r'Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result.stdout)
                
                for ip in nmap_ips:
                    if ip != pivot_ip and ip not in discovered_ips:
                        discovered_ips.append(ip)
                        logger.info(f"Found device via {scan_type}: {ip}")
                        
            else:
                logger.warning(f"{scan_type} sweep failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.warning(f"{scan_type} sweep timed out")
        except Exception as e:
            logger.warning(f"Error in {scan_type} sweep: {e}")
    
    
    logger.info(f"Network discovery complete: found {len(discovered_ips)} devices")
    return discovered_ips

def scan_host_directly(target_ip):

    ports_processes = []
    found_mac = None

    # Build scan commands list based on flags
    scan_commands = [
        f"nmap -Pn -sS --top-ports 1000 {target_ip}",     # SYN scan (fastest, most ports)
        f"nmap -Pn -sT --top-ports 500 {target_ip}",      # Connect scan (more reliable)
    ]
    scan_types = ["SYN scan", "TCP connect scan"]
    timeouts = [90, 120]


    if UDP_SCAN:
        scan_commands.append(f"nmap -Pn -sU --top-ports 100 {target_ip}")  # UDP scan (for UDP services)
        scan_types.append("UDP scan")
        timeouts.append(180)  # UDP scans need more time

    for i, command in enumerate(scan_commands):
        try:
            scan_type = scan_types[i]
            timeout = timeouts[i]
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                scan_ports = []
                
                for line in lines:
    
                    if '/tcp' in line and 'open' in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            port_proto = parts[0]
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            
                            if state == 'open':
                                port = port_proto.split('/')[0]
                                scan_ports.append((port, service + '/tcp'))
                    
        
                    elif '/udp' in line and ('open' in line or 'open|filtered' in line):
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            port_proto = parts[0]
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            
                            if 'open' in state:
                                port = port_proto.split('/')[0]
                                scan_ports.append((port, service + '/udp'))
                    
           
                    elif 'MAC Address:' in line and not found_mac:
                        mac_match = re.search(r'MAC Address: ([0-9A-F:]{17})', line)
                        if mac_match:
                            found_mac = mac_match.group(1)
                
                # Add unique ports to results
                for port_info in scan_ports:
                    if port_info not in ports_processes:
                        ports_processes.append(port_info)
                
                if scan_ports:
                    logger.info(f"{scan_type} found {len(scan_ports)} open ports on {target_ip}")
                    
            else:
                logger.warning(f"{scan_type} failed for {target_ip}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.warning(f"{scan_type} timed out for {target_ip}")
        except Exception as e:
            logger.warning(f"Error in {scan_type} for {target_ip}: {e}")
    
    logger.info(f"Completed scanning {target_ip}: {len(ports_processes)} total open ports")
    return ports_processes, found_mac

# Enhanced scan function with cycle detection and deduplication  
# scan the internal network for devices, and scan their ports
# return dictionary of key = value: source ip = [[found_ips],[found_macs], [(ports,service)]]
def scan_device_and_networks_recursive(device_ip, username, password, hop_path, current_depth=0, max_depth=10):

    global all_info, usernames, passwords, recursively_scanned_devices

    if current_depth >= max_depth:
        logger.warning(f"Reached maximum depth ({max_depth}) at {device_ip}, stopping recursion")
        return

  

    # Store credentials and hop path
    ssh_credentials[device_ip] = (username, password)
    ssh_hop_paths[device_ip] = hop_path

    remote_success, remote_mac_key = extract_remote_device_info(device_ip, username, password)

    if not remote_success:
        return


    # Get the network information we extracted
    device_info = all_info[remote_mac_key]
    device_ips = device_info[1]      # Device's own IPs
    device_masks = device_info[3]    # Network masks
    device_ranges = device_info[4]   # Network ranges to scan

    # Build a list of IPs to exclude from scanning:
    # 1. Current device's IPs
    # 2. IP of previous device
   
    exclude_ips_set = set(device_ips)
    exclude_ips_list = list(exclude_ips_set)
    exclude_ips_list.append(hop_path[-1])

    # First, perform ping sweeps on all networks to discover hosts
    # This happens BEFORE creating the SSH tunnel since ping sweeps use regular SSH
    all_discovered_hosts = []  
    network_to_hosts = {}  

    for idx, net_ip in enumerate(device_ips):
        network_range = device_ranges[idx]
        network_mask = device_masks[idx]
        network_id = get_network_identifier(net_ip, network_mask)

        # Skip if already scanned from this device
        network_scan_key = f"{network_id}_via_mac_{remote_mac_key}"
        if is_network_already_scanned(network_scan_key):
            continue

        mark_network_as_scanned(network_scan_key)

        # Run ping sweep
        network_base = ".".join(net_ip.split(".")[:3])
        logger.info(f"{'  ' * current_depth}Ping sweep on {network_base}.0/24 from {device_ip}")

        discovered_hosts = ping_sweep_remote(
            device_ip, username, password,
            network_base,
            network_range[0],
            network_range[1],
            exclude_ips=exclude_ips_list  
        )

        if not discovered_hosts:
        
            continue

        network_to_hosts[network_id] = discovered_hosts
        all_discovered_hosts.extend(discovered_hosts)


    if not all_discovered_hosts:
        return
    
    # Now create SSH tunnel for port scanning
    tunnel_port = create_ssh_tunnel(device_ip, username, password, hop_path=hop_path)

    if not tunnel_port:
        return

   
    time.sleep(2)

    # Now scan ports on all discovered hosts
    for network_id, discovered_hosts in network_to_hosts.items():

        for host_ip in discovered_hosts:

            if host_ip == device_ip:
                continue
            
            if host_ip in hop_path:
                continue

            if host_ip in recursively_scanned_devices:
                continue

            logger.info(f"{'  ' * current_depth}Scanning ports on {host_ip}")
            host_ports, host_mac = scan_host_ports_proxy(host_ip, tunnel_port, tunnel_device_ip=device_ip)

            has_ssh = any(p[0] == '22' for p in host_ports)

            # Add to topology
            path_str = '->'.join(hop_path + [host_ip])
            add_device_to_topology(
                host_ip, host_mac, host_ports, network_id,
                path_str,
                ssh_accessible=has_ssh
            )
              
            if has_ssh:

                new_hop_path = hop_path + [device_ip]

               
                forward_result = ensure_local_forward_chain(host_ip, new_hop_path)

                if forward_result is None and len(new_hop_path) > 0:

                    continue


                # Try SSH with known credentials
                for try_user, try_pass in zip(usernames, passwords):
                    if attempt_ssh_connection(host_ip, try_user, try_pass, hop_path=new_hop_path):
                        logger.info(f"{'  ' * current_depth} SSH successful to {host_ip} via multi-hop")

                        
                        recursively_scanned_devices.add(host_ip)

                        scan_device_and_networks_recursive(
                            host_ip, try_user, try_pass,
                            new_hop_path,
                            current_depth + 1,
                            max_depth
                        )
                        break  # Stop trying credentials once successful
          
        



def scan_network(joined_macs):
   
    global all_info, tunnel_counter, usernames, passwords, discovered_devices, network_topology, ssh_credentials
    
    ranges = all_info[joined_macs][4]
    ips = all_info[joined_macs][1]
    masks = all_info[joined_macs][3]
    returned_dict = {}
    
    # Scan from pivot device first
    for index in range(len(ips)):
        pivot_ip = ips[index]
        network_range = ranges[index]
        mask = masks[index]

        # Test and store pivot credentials first (before any scanning)
        # This ensures pivot credentials are available for creating local forwards
        if pivot_ip not in ssh_credentials:
            pivot_creds_found = False

            for username, password in zip(usernames, passwords):

                test_command = (
                    f"sshpass -p '{password}' ssh "
                    f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                    f"-o ConnectTimeout=10 "
                    f"{username}@{pivot_ip} 'echo connected'"
                )

                try:
                    result = subprocess.run(
                        test_command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=15,
                        universal_newlines=True
                    )

                    if result.returncode == 0 and 'connected' in result.stdout:
                        ssh_credentials[pivot_ip] = (username, password)
                        pivot_creds_found = True
                        break
                  
                except Exception as e:
                    logger.debug(f"Error testing credential {username} for pivot: {e}")

            if not pivot_creds_found:
                logger.warning(f"No valid credentials found for pivot {pivot_ip}")
                logger.warning(f"This may cause issues with multi-hop SSH forwarding")

        network_id = get_network_identifier(pivot_ip, mask)
        

        if is_network_already_scanned(network_id):
            continue
            
        mark_network_as_scanned(network_id)
        
        first_three_octets = pivot_ip.split(".")[:3]
        first_three_octets = ".".join(first_three_octets)
        
        discovered_ips = discover_network_devices(
            first_three_octets, 
            network_range[0], 
            network_range[1], 
            pivot_ip
        )
        
        # Filter out already discovered devices
        new_devices = [ip for ip in discovered_ips if not is_device_already_discovered(ip)]

        if new_devices:
            returned_dict[pivot_ip] = [new_devices, [], []]
        else:
            # ping sweep fallback
            ping_command = f"""
for i in $(seq {network_range[0]} {network_range[1]}); do
    (ping -c 1 -W 1 {first_three_octets}.$i > /dev/null 2>&1 && echo {first_three_octets}.$i) &
done
wait
"""
            try:
                result = subprocess.run(ping_command, shell=True, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
                ping_ips = [line.strip() for line in result.stdout.split('\n') if line.strip() and line.strip() != pivot_ip]

                if ping_ips:
                    logger.info(f"Ping sweep found {len(ping_ips)} devices: {ping_ips}")
                    new_devices = [ip for ip in ping_ips if not is_device_already_discovered(ip)]
                    if new_devices:
                        returned_dict[pivot_ip] = [new_devices, [], []]
                else:
                    logger.info(f"No devices found on network {network_id}, skipping")
                    if network_id not in returned_dict:
                        returned_dict[pivot_ip] = [[], [], []]
                    continue
            except Exception as e:
                if network_id not in returned_dict:
                    returned_dict[pivot_ip] = [[], [], []]
                continue

        # Now scan individual hosts and attempt SSH tunneling
        # Since we're scanning FROM the pivot (not through it), start with empty path
        current_path = []

        for discovered_ip in new_devices:

            if discovered_ip in recursively_scanned_devices:
                continue

            ports_info, mac_addr = scan_host_directly(discovered_ip)

       
            add_device_to_topology(
                discovered_ip, mac_addr, ports_info, network_id,
                f"pivot->{discovered_ip}",
                ssh_accessible=any(port[0] == '22' for port in ports_info)
            )

            ssh_success = False

            # Check if device has SSH port open
            has_ssh = any(port[0] == '22' for port in ports_info)

            # Check if we should create tunnel (avoid cycles)
            if should_create_ssh_tunnel(discovered_ip, current_path) and has_ssh:
                logger.info(f"Device {discovered_ip} has SSH open, attempting credentials (have {len(usernames)} credentials to try)")

                if len(usernames) == 0:
                    logger.warning("No credentials available! Check credentials.txt file")

                for username, password in zip(usernames, passwords):
                    logger.debug(f"Trying credential {username}:{'*' * len(password)}")

                    ssh_credentials[discovered_ip] = (username, password)

                    if attempt_ssh_connection(discovered_ip, username, password, hop_path=current_path):
                        logger.info(f"SSH access successful to {discovered_ip} with {username}")
                        ssh_success = True

                    
                        ssh_access_paths[discovered_ip] = current_path + [discovered_ip]

                        # Scan this device and all its networks (unlimited depth)
                        try:
                            scan_device_and_networks_recursive(
                                discovered_ip, username, password,
                                hop_path=[pivot_ip],  # Include pivot so its IPs are excluded from scans
                                current_depth=1,
                                max_depth=20  # Support up to 20 hops!
                            )
                        except Exception as e:
                            logger.error(f"Error during recursive scan of {discovered_ip}: {e}")

                        break  # Stop trying credentials once successful

                if not ssh_success:
                    logger.info(f"No valid SSH credentials found for {discovered_ip}")
            elif not has_ssh:
                logger.info(f"Device {discovered_ip} has no SSH port open, skipping SSH attempt")
            else:
                logger.info(f"SSH tunnel creation skipped for {discovered_ip} (cycle prevention or already accessible)")

            # Mark device as fully scanned AFTER SSH attempt (whether successful or not)
            # This prevents re-attempting SSH on the same device in future network scans
            recursively_scanned_devices.add(discovered_ip)

            # All network scanning is now handled by scan_device_and_networks_recursive()

            # Update main returned data structure
            if pivot_ip not in returned_dict:
                returned_dict[pivot_ip] = [[], [], []]
            
            returned_dict[pivot_ip][0].append(discovered_ip)
            returned_dict[pivot_ip][1].append(mac_addr)
            returned_dict[pivot_ip][2].append(ports_info)

       


    if len(network_topology) > 0:
        logger.info("=" * 60)
        logger.info(f"NETWORK MAPPING COMPLETE - Discovered {len(network_topology)} unique devices")
        logger.info("=" * 60)

        # Log all devices in topology
        for ip, data in network_topology.items():
            networks_list = list(data['networks'])
            ssh_status = "SSH" if data['ssh_accessible'] else "NO-SSH"
            logger.info(f"  [{ssh_status}] {ip} on {len(networks_list)} network(s): {networks_list}")

        # Log devices found on multiple networks (potential cycles)
        multi_network_devices = {ip: data for ip, data in network_topology.items()
                               if len(data['networks']) > 1}

        if multi_network_devices:
            logger.info("")
            logger.info(f"Found {len(multi_network_devices)} devices on multiple networks (potential cycles):")
            for ip, data in multi_network_devices.items():
                networks = list(data['networks'])
                logger.info(f" {ip}: {networks}")

        logger.info("=" * 60)

    return returned_dict      
        
    
      


      
# to be run from the pivot machine
credentials_file = "credentials.txt"

# store usernames and passwords separately to be used
usernames = []
passwords = []
logger.info(f"Loading credentials from {credentials_file}")
try:
    with open("credentials.txt", "r") as file_obj:
        content = file_obj.read()
        lines = content.split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):  # Skip empty lines and comments
                continue
            if ":" not in line:
                logger.warning(f"Invalid credential format (missing colon): {line}")
                continue
            credential = line.split(":", 1)  # Split on first colon only
            if len(credential) >= 2:
                usernames.append(credential[0])
                passwords.append(credential[1])
                logger.info(f"Loaded credential for user: {credential[0]}")
            else:
                logger.warning(f"Invalid credential format: {line}")

    logger.info(f"Total credentials loaded: {len(usernames)}")
    if len(usernames) == 0:
        logger.error("WARNING: No credentials loaded! SSH attempts will fail.")
except FileNotFoundError:
    logger.error(f"ERROR: Credentials file '{credentials_file}' not found!")
    logger.error("Create a credentials.txt file with format: username:password")
except Exception as e:
    logger.error(f"Error loading credentials: {e}")

# dictionary of all devices and their information
# format: key = hostname, value = [[interfaces], [ips],[masks], [network ranges], [ports], [processes]]  
# network range format: [first device IP, last device IP]
all_info = dict()

# Main execution will be moved to the end of the file

def is_headless():
    import os
    return (not os.environ.get('DISPLAY') and 
            not os.environ.get('WAYLAND_DISPLAY') and 
            not os.environ.get('XDG_SESSION_TYPE'))

def generate_ascii_network_map(device_info, discovered_networks):
    """Generate ASCII art network topology with cycle detection for headless systems"""
    global network_topology
    ascii_map = []


    

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


    ascii_map.append("+- PIVOT DEVICE -----------------------------------------+")
    ascii_map.append(f"| [P] {pivot_name:<45} |")
    ascii_map.append(f"| IPs: {', '.join(pivot_ips):<43} |")
    ascii_map.append(f"| Open Ports: {len(pivot_ports)} services running{'':<29} |")
    ascii_map.append("+-----------------------------------------------------+")
    ascii_map.append("    |")

    # Use network_topology instead of discovered_networks for complete view
    logger.info(f"Generating map from network_topology with {len(network_topology)} devices")

    if not network_topology:
        ascii_map.append("    └─ No devices discovered")
        return '\n'.join(ascii_map)

    # Group devices by network
    networks_dict = {}
    for ip, data in network_topology.items():
        for network in data['networks']:
            if network not in networks_dict:
                networks_dict[network] = []
            networks_dict[network].append((ip, data))

    # Process each network segment
    for idx, (network_id, devices) in enumerate(networks_dict.items()):
        # Network segment header

        if idx < len(networks_dict) - 1:
            ascii_map.append("    +- NETWORK SEGMENT --------------------------------")
        else:
            ascii_map.append("    \\- NETWORK SEGMENT --------------------------------")

        ascii_map.append(f"    |  [N] Network: {network_id}")
        ascii_map.append(f"    |  Discovered: {len(devices)} devices")
        ascii_map.append("    |")

        # List discovered devices
        for i, (ip, data) in enumerate(devices):
            mac = data['mac'] if data['mac'] else "Unknown"
            ports = data['ports']

            is_last_device = (i == len(devices) - 1)
            is_last_network = (idx == len(networks_dict) - 1)
            
            # SSH accessibility check from topology data
            ssh_accessible = data['ssh_accessible']

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
            ascii_map.append("+== CROSS-NETWORK DEVICES (Potential Cycles) ============+")
            for ip, data in multi_network_devices.items():
                networks = list(data['networks'])
                ascii_map.append(f"| [X] {ip:<15} Networks: {', '.join(networks):<16} |")
            ascii_map.append("+=========================================================+")
    
    # Add legend
    ascii_map.append("")
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
    

def cleanup_ssh_tunnels():
    global ssh_tunnels, ssh_processes, FIXED_SOCKS_PORT, local_port_forwards, local_forward_processes

    logger.info("Cleaning up SSH tunnels and local port forwards...")

    # First, kill tracked local port forward processes
    for target_ip, process in list(local_forward_processes.items()):
        try:
            local_port = local_port_forwards.get(target_ip, "unknown")
            process.terminate()
            process.wait(timeout=3)
        except:
            try:
                process.kill()
            except:
                pass

    for target_ip, process in list(ssh_processes.items()):
        try:
            process.terminate()
            process.wait(timeout=3)
        except:
            try:
                process.kill()
            except:
                pass


    force_kill_port_9050()

    # Kill any remaining SSH tunnel and local forward processes
    try:
        subprocess.run("pkill -f 'ssh.*-D.*-N'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run("pkill -f 'ssh.*-L.*-N'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        pass

    # Remove temporary proxychains config files
    try:
        subprocess.run("rm -f /tmp/proxychains_*.conf", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info("Removed temporary proxychains configuration files")
    except:
        pass

    ssh_tunnels.clear()
    ssh_processes.clear()
    ssh_credentials.clear()
    ssh_hop_paths.clear()
    local_port_forwards.clear()
    local_forward_processes.clear()

    time.sleep(2)


def save_results_to_json(results, filename="network_scan_results.json"):
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving results: {e}")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Automated Network Discovery and SSH Tunneling Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Standard scan (no UDP, no ARP)
  %(prog)s -udp               # Include UDP port scanning (slower)
  %(prog)s -arp               # Include ARP table checking
  %(prog)s -udp -arp          # Include both UDP scanning and ARP checking

Notes:
  -udp: Enables UDP port scanning (slower but more comprehensive)
  -arp: Enables ARP table checking for device discovery
        """)

    parser.add_argument(
        '-udp',
        action='store_true',
        help='Include UDP port scanning (slower but more thorough)'
    )

    parser.add_argument(
        '-arp',
        action='store_true',
        help='Include ARP table checking for device discovery'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='Network Mapper v2.0'
    )

    return parser.parse_args()

if __name__ == "__main__":
 
    args = parse_arguments()

  
    UDP_SCAN = args.udp
    ARP_SCAN = args.arp

    logger.info("Starting network mapping from pivot device")
    logger.info(f"Scan options: UDP={'enabled' if UDP_SCAN else 'disabled'}, ARP={'enabled' if ARP_SCAN else 'disabled'}")

    if UDP_SCAN:
        logger.info("UDP scanning enabled - may take significantly longer")
    if ARP_SCAN:
        logger.info("ARP table checking enabled for device discovery")
    
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
            
            # network topology visualization
            logger.info("Generating network topology map...")
            map_file = generate_network_map(all_info, found_devices)
            
            if map_file:
                logger.info(f"Network topology visualization saved as {map_file}")
            
            logger.info("Network mapping completed successfully")
            print(f"\\n" + "="*60)
            print(f"NETWORK SCAN COMPLETE!")
            print(f"="*60)
            print(f"Results saved to: network_scan_results.json")
            print(f"Detailed report: network_details.txt")
            
            if map_file == "network_topology_ascii.txt":
                print(f"Network map: ASCII format (displayed above)")
                print(f"ASCII map file: network_topology_ascii.txt")
                if is_headless():
                    print(f"💡 Note: Running in headless mode - graphical map not generated")
            else:
                print(f"Network map: {map_file}")
                print(f"ASCII map: network_topology_ascii.txt")
            
            print(f"="*60)
            
        else:
            logger.warning("Device already scanned or extraction failed")
            
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error during network mapping: {e}")
    finally:
        cleanup_ssh_tunnels()






      
      
      

      
  
    

    
  