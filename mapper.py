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
UDP_SCAN = False  # Default: no UDP scanning (slow)
ARP_SCAN = False  # Default: no ARP table checking

# Global variables for SSH tunneling and cycle detection
FIXED_SOCKS_PORT = 9050  # FIXED: Only port 9050 works for dynamic forwarding
ssh_tunnels = {}  # Track active SSH tunnels: {ip: port (always 9050)}
ssh_processes = {}  # Track SSH tunnel processes to keep them alive: {ip: subprocess.Popen}
ssh_credentials = {}  # Track SSH credentials for each device: {ip: (username, password)}
ssh_hop_paths = {}  # Track the hop path to reach each device: {ip: [hop1_ip, hop2_ip, ...]}

# Local port forwarding for multi-hop SSH access
# Maps device IP to local port that forwards to it: {device_ip: local_port}
local_port_forwards = {}
local_forward_processes = {}  # Track local forward processes: {device_ip: subprocess.Popen}
next_local_port = 10000  # Start assigning local forward ports from 10000

# Note: We no longer need port candidates - always using port 9050
discovered_devices = set()  # Track all discovered device IPs to prevent duplicates
recursively_scanned_devices = set()  # Track devices we've SSH'd into and recursively scanned
scanned_networks = set()  # Track scanned network ranges to prevent re-scanning
device_network_map = {}  # Track which networks each device belongs to
ssh_access_paths = {}  # Track SSH access paths to prevent cycles
network_topology = {}  # Complete topology with cross-references

# first within pivot, we need to enumerate first private network
# user should be sudo'd into pivot with "sudo su"

def extract_networks():
    """Extract network interfaces and their IP addresses"""
    command = ["ip", "a"]

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True) 
        output = result.stdout
        
        interfaces = []
        networks = []
        macs = []
        
        logger.info("Extracting network interfaces...")
        logger.debug(f"ip a output:\n{output}")
        
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
                    logger.debug(f"Found network {network} on interface {interface_name}")
                
                # Look for MAC address
                mac_match = re.search(r'link/ether\s+([0-9a-f:]{17})', line, re.IGNORECASE)
                if mac_match and not interface_mac:
                    interface_mac = mac_match.group(1)
                    logger.debug(f"Found MAC {interface_mac} on interface {interface_name}")
            
            # Add each network found on this interface
            for network in interface_networks:
                interfaces.append(interface_name)
                networks.append(network)
                macs.append(interface_mac if interface_mac else "unknown")
        
        logger.info(f"Extracted {len(networks)} networks from {len(set(interfaces))} interfaces")
        for i, (iface, net) in enumerate(zip(interfaces, networks)):
            logger.info(f"  Interface {iface}: {net}")
            
        return networks, interfaces, macs
        
    except Exception as e:
        logger.error(f"Error extracting networks: {e}")
        return [], [], []
      
    
      
# given a list of networks and their corresponding interfaces, only return the interfaces 
# and networks that are private that will be scanned        
def extract_private(networks, interfaces, macs):
    """Filter for private networks (RFC 1918) with proper parsing"""
    returned_networks = []
    returned_interfaces = []
    returned_macs = []
    
    logger.info("Filtering for private networks...")
    
    for index in range(len(networks)):
        network = networks[index]
        interface = interfaces[index]
        mac = macs[index]
        
        try:
            # Split IP from CIDR notation (e.g., "10.5.0.1/24" -> "10.5.0.1")
            ip_part = network.split("/")[0]
            octets = ip_part.split(".")
            
            if len(octets) >= 2:
                first_octet = int(octets[0])
                second_octet = int(octets[1])
                
                # RFC 1918 private address ranges
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
                else:
                    logger.debug(f"Skipping public network: {network}")
            else:
                logger.warning(f"Invalid IP format: {network}")
                
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
  
      
 # ip is device ip
 # mask ranges from 24-31 
 # return [first device IP, last device IP] 
 
def get_network_range(ip, mask):
    """Calculate network range for scanning with proper validation"""
    try:
        mask_int = int(mask)
        if mask_int < 8 or mask_int > 30:
            logger.warning(f"Unusual subnet mask /{mask_int}, using /24 instead")
            mask_int = 24
        
        octets = ip.split(".")
        if len(octets) != 4:
            raise ValueError(f"Invalid IP address format: {ip}")
            
        last_octet = int(octets[3])
        
        # Calculate network size and range
        host_bits = 32 - mask_int
        network_size = 2 ** host_bits
        
        # For /24 networks (most common), scan full range
        if mask_int == 24:
            return [1, 254]
        
        # For other subnet sizes, calculate proper range
        network_start = (last_octet // network_size) * network_size
        first_device = network_start + 1
        last_device = network_start + network_size - 2
        
        # Ensure we don't scan outside valid range
        first_device = max(1, min(first_device, 254))
        last_device = max(first_device, min(last_device, 254))
        
        logger.info(f"Calculated scan range for {ip}/{mask}: {first_device}-{last_device}")
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
      # ports and processes associated to those ports
      
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
    """Extract device network information with detailed logging"""
    global all_info
    
    logger.info("=== STARTING DEVICE EXTRACTION ===")
    
    # Extract all networks on this machine       
    all_networks, all_interfaces, all_macs = extract_networks()
    logger.info(f"Raw extraction found {len(all_networks)} networks: {all_networks}")
    
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
        # If no valid MACs, use hostname as fallback identifier
        import socket
        hostname = socket.gethostname()
        mac_key = f"host_{hostname.replace('.', '_').lower()}"
        logger.warning(f"No valid MAC addresses found, using hostname-based key: {mac_key}")
    else:
        # Use ONLY the first (lowest) MAC as device identifier
        # This ensures the same device always has the same ID regardless of how many interfaces are visible
        sorted_macs = sorted(valid_macs)
        mac_key = sorted_macs[0]  # Use first MAC only
        logger.debug(f"Created stable device ID from first MAC (out of {len(sorted_macs)}): {mac_key}")

    if mac_key not in all_info:
        hostname = get_hostname()
        logger.info(f"Device hostname: {hostname}")
        
        device_ips = []
        masks = []
        network_ranges = []
        
        for i, network in enumerate(networks):
            logger.info(f"Processing network {i+1}/{len(networks)}: {network}")
            
            try:
                information = network.split("/")
                if len(information) != 2:
                    logger.error(f"Invalid network format: {network}")
                    continue
                    
                device_ip = information[0]
                mask = information[1]
                network_range = get_network_range(device_ip, mask)
                
                logger.info(f"  Device IP: {device_ip}")
                logger.info(f"  Mask: /{mask}")
                logger.info(f"  Calculated scan range: {network_range[0]}-{network_range[1]}")
                
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
        logger.info(f"Found {len(ports)} open ports on pivot device")
        
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

def create_local_port_forward(target_ip, target_port, via_ip, via_username, via_password, via_local_port=None):
    """
    Create a local port forward to access target_ip through via_ip

    Args:
        target_ip: IP of the device we want to reach
        target_port: Port on target device (usually 22 for SSH)
        via_ip: IP of intermediate device (or None for direct connection)
        via_username: Username for intermediate device
        via_password: Password for intermediate device
        via_local_port: If via_ip is also forwarded, the local port to reach it (None if direct)

    Returns:
        local_port: The local port that forwards to target_ip, or None if failed
    """
    global next_local_port, local_port_forwards, local_forward_processes

    # Check if we already have a forward for this device
    if target_ip in local_port_forwards:
        logger.info(f"Local port forward already exists for {target_ip} on port {local_port_forwards[target_ip]}")
        return local_port_forwards[target_ip]

    # Assign a new local port
    local_port = next_local_port
    next_local_port += 1

    # Build the SSH command for local port forwarding
    if via_local_port is None:
        # Direct connection to via_ip
        ssh_cmd = (
            f"sshpass -p '{via_password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-L {local_port}:{target_ip}:{target_port} "
            f"-N {via_username}@{via_ip}"
        )
        logger.info(f"Creating local port forward: localhost:{local_port} -> {via_ip} -> {target_ip}:{target_port}")
    else:
        # Multi-hop: Connect through existing local forward
        ssh_cmd = (
            f"sshpass -p '{via_password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-p {via_local_port} "
            f"-L {local_port}:{target_ip}:{target_port} "
            f"-N {via_username}@localhost"
        )
        logger.info(f"Creating multi-hop local port forward: localhost:{local_port} -> localhost:{via_local_port} -> {target_ip}:{target_port}")

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

        # Give it a moment to establish
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

def attempt_ssh_connection(target_ip, username, password, hop_path=None):
    """Test if SSH connection is possible to a target (supports multi-hop via local port forwards)"""
    global local_port_forwards, ssh_credentials

    # Determine if we need local port forward (multi-hop) or direct connection
    if hop_path and len(hop_path) > 0:
        # Multi-hop: need to use local port forward
        # hop_path is the path TO the intermediate device, e.g., [pivot_ip] or [pivot_ip, device_a_ip]
        logger.info(f"Testing SSH connection to {target_ip} via hop path {hop_path} with user {username}")

        # Check if we already have a local port forward to this device
        if target_ip in local_port_forwards:
            local_port = local_port_forwards[target_ip]
            logger.debug(f"Using existing local port forward on port {local_port}")
        else:
            # We need to establish a forward chain
            # The last device in hop_path is the one we SSH through
            via_ip = hop_path[-1]

            if via_ip not in ssh_credentials:
                logger.error(f"No credentials found for intermediate hop {via_ip}")
                return False

            via_username, via_password = ssh_credentials[via_ip]

            # Determine if via_ip itself needs a forward (if hop_path has more than 1 hop)
            if len(hop_path) > 1:
                # via_ip is also accessed through a forward
                if via_ip not in local_port_forwards:
                    logger.error(f"No local port forward exists for intermediate hop {via_ip}")
                    return False
                via_local_port = local_port_forwards[via_ip]
            else:
                # via_ip is directly accessible (no forward needed)
                via_local_port = None

            # Create the local port forward to target_ip
            logger.info(f"Creating local port forward to {target_ip} through {via_ip}")
            local_port = create_local_port_forward(
                target_ip=target_ip,
                target_port=22,
                via_ip=via_ip,
                via_username=via_username,
                via_password=via_password,
                via_local_port=via_local_port
            )

            if not local_port:
                logger.error(f"Failed to create local port forward to {target_ip}")
                return False

        # Now test SSH connection through the local forward
        test_command = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=10 "
            f"-p {local_port} {username}@localhost 'echo connected'"
        )
        logger.debug(f"Testing SSH via localhost:{local_port}")
    else:
        # Direct connection
        logger.info(f"Testing SSH connection to {target_ip} (direct) with user {username}")
        test_command = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=10 "
            f"{username}@{target_ip} 'echo connected'"
        )

    # Log the full command with password masked
    masked_cmd = test_command.replace(password, '***PASSWORD***')
    logger.info(f"[SSH COMMAND] Connection test: {masked_cmd}")

    try:
        result = subprocess.run(test_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15)
        if result.returncode == 0:
            logger.info(f"✓ SSH connection successful to {target_ip} with {username}")
            return True
        else:
            logger.info(f"✗ SSH connection failed to {target_ip} with {username}: {result.stderr.strip()[:100]}")
            return False
    except Exception as e:
        logger.warning(f"✗ SSH connection exception for {target_ip} with {username}: {e}")
        return False

def execute_remote_command(target_ip, username, password, command, timeout=30):
    """Execute a command on a remote device via SSH (supports multi-hop via local forwards) and return the output"""
    global local_port_forwards

    # Check if we have a local port forward for this device (multi-hop)
    if target_ip in local_port_forwards:
        local_port = local_port_forwards[target_ip]
        logger.debug(f"Executing remote command on {target_ip} via local port forward (localhost:{local_port})")
        ssh_command = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=10 "
            f"-p {local_port} {username}@localhost '{command}'"
        )
    else:
        # Direct connection
        logger.debug(f"Executing remote command on {target_ip} (direct)")
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

def ping_sweep_remote(target_ip, username, password, network_base, start_range, end_range, exclude_ips=None):
    """Run a fast ping sweep directly on the remote device (much faster than proxychains TCP scan)

    Args:
        exclude_ips: List of IPs to exclude (e.g., the device's own IPs to prevent scanning itself)
    """
    if exclude_ips is None:
        exclude_ips = []

    logger.info(f"Running ping sweep on {target_ip} for {network_base}.{start_range}-{end_range}")
    if exclude_ips:
        logger.info(f"Excluding {len(exclude_ips)} IPs (device's own interfaces): {exclude_ips}")

    # Build a bash command to ping all IPs in parallel
    # Using background jobs with & and wait for maximum speed
    ping_command = f"""
for i in $(seq {start_range} {end_range}); do
    (ping -c 1 -W 1 {network_base}.$i > /dev/null 2>&1 && echo {network_base}.$i) &
done
wait
"""

    # Execute the ping sweep on the remote device
    success, output = execute_remote_command(target_ip, username, password, ping_command, timeout=120)

    if not success:
        logger.warning(f"Ping sweep failed on {target_ip}")
        return []

    # Parse output to get list of responding IPs
    discovered_ips = []
    for line in output.strip().split('\n'):
        line = line.strip()
        # Check if it's a valid IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
            # Exclude: target device and device's own IPs
            if line != target_ip and line not in exclude_ips:
                discovered_ips.append(line)
                logger.info(f"Found live host via ping: {line}")
            elif line in exclude_ips:
                logger.debug(f"Skipping {line} (device's own IP)")

    logger.info(f"Ping sweep on {target_ip} found {len(discovered_ips)} live hosts (excluded {len(exclude_ips)} own IPs)")
    return discovered_ips

def extract_remote_device_info(target_ip, username, password):
    """Extract network information from a remote device via SSH"""
    global all_info

    logger.info(f"=== EXTRACTING REMOTE DEVICE INFO FROM {target_ip} ===")

    # Execute 'ip a' on remote device
    success, ip_output = execute_remote_command(target_ip, username, password, "ip a", timeout=15)
    if not success:
        logger.error(f"Failed to get network info from {target_ip}")
        return False, ""

    # Execute 'hostname' on remote device
    success, hostname_output = execute_remote_command(target_ip, username, password, "hostname", timeout=10)
    if not success:
        logger.warning(f"Failed to get hostname from {target_ip}")
        hostname = f"remote_{target_ip.replace('.', '_')}"
    else:
        hostname = hostname_output.strip().split(".")[0]

    # Execute 'ss -ntlp' on remote device to get open ports
    success, ss_output = execute_remote_command(target_ip, username, password, "ss -ntlp", timeout=15)
    if not success:
        logger.warning(f"Failed to get port info from {target_ip}")
        ports = []
        processes = []
    else:
        # Parse ss output (similar to extract_ports logic)
        ports = []
        processes = []
        lines = ss_output.split("\n")[1:]  # Skip header
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

    # Parse ip a output (similar to extract_networks logic)
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
                logger.debug(f"Found network {network} on interface {interface_name} (remote: {target_ip})")

            # Look for MAC address
            mac_match = re.search(r'link/ether\s+([0-9a-f:]{17})', line, re.IGNORECASE)
            if mac_match and not interface_mac:
                interface_mac = mac_match.group(1)
                logger.debug(f"Found MAC {interface_mac} on interface {interface_name} (remote: {target_ip})")

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

                # RFC 1918 private address ranges
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
    # IMPORTANT: Use FIRST (lowest) MAC address as stable device identifier
    # Normalize to lowercase and filter out "unknown" MACs
    valid_macs = [mac.lower() for mac in returned_macs if mac != "unknown"]
    if not valid_macs:
        # If no valid MACs, use target IP as fallback identifier
        mac_key = f"ip_{target_ip.replace('.', '_')}"
        logger.warning(f"No valid MAC addresses found, using IP-based key: {mac_key}")
    else:
        # Use ONLY the first (lowest) MAC as device identifier
        # This ensures the same device always has the same ID regardless of how many interfaces are visible
        sorted_macs = sorted(valid_macs)
        mac_key = sorted_macs[0]  # Use first MAC only
        logger.debug(f"Created stable device ID from first MAC (out of {len(sorted_macs)}): {mac_key}")

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

                logger.info(f"  Device IP: {device_ip}")
                logger.info(f"  Mask: /{mask}")
                logger.info(f"  Calculated scan range: {network_range[0]}-{network_range[1]}")

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
            logger.info(f"  Existing path length: {existing_path_length}, Current path length: {current_path_length}")
            logger.info(f"  Existing path: {ssh_access_paths[target_ip]}")
            return False

    # Check for potential cycles
    if target_ip in current_path:
        logger.warning(f"Cycle detected: {target_ip} already in path {current_path}")
        return False

    logger.debug(f"SSH tunnel check passed for {target_ip}, current path: {current_path}")
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

def is_port_available(port):
    """Check if a local port is available for binding"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
            return True
    except OSError:
        return False

def get_available_port():
    """Get next available port from candidates list"""
    global used_ports
    
    # First try our preferred candidates
    for port in SOCKS_PORT_CANDIDATES:
        if port not in used_ports and is_port_available(port):
            used_ports.add(port)
            return port
    
    # If all candidates are taken, try random high ports
    for _ in range(50):  # Try up to 50 random ports
        port = random.randint(10000, 65000)
        if port not in used_ports and is_port_available(port):
            used_ports.add(port)
            return port
    
    return None

def test_socks_proxy(port, timeout=10):
    """Test if SOCKS proxy is working on given port"""
    logger.info(f"Testing SOCKS proxy on 127.0.0.1:{port}")

    try:
        import socks
        logger.debug(f"Using Python socks module to test proxy on port {port}")
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", port)
        s.settimeout(timeout)
        # Try to connect to a known good address
        s.connect(("8.8.8.8", 53))  # Google DNS
        s.close()
        logger.info(f"✓ SOCKS proxy on port {port} is responding (Python socks test)")
        return True
    except Exception as e:
        logger.debug(f"Python socks test failed: {e}")
        # Fallback test using curl if socks module not available
        try:
            test_cmd = f"timeout {timeout} curl -x socks5://127.0.0.1:{port} -s http://www.google.com --max-time {timeout}"
            logger.debug(f"Trying curl test: {test_cmd}")
            result = subprocess.run(test_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout+2)
            if result.returncode == 0:
                logger.info(f"✓ SOCKS proxy on port {port} is responding (curl test)")
                return True
            else:
                logger.warning(f"✗ SOCKS proxy on port {port} not responding (curl failed)")
                return False
        except Exception as e2:
            logger.warning(f"✗ SOCKS proxy on port {port} not responding (curl exception: {e2})")
            return False

def build_proxy_command_chain(target_ip):
    """Build ProxyCommand chain for multi-hop SSH connections"""
    global ssh_hop_paths, ssh_credentials

    if target_ip not in ssh_hop_paths or not ssh_hop_paths[target_ip]:
        # Direct connection, no proxy command needed
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
            # First hop - direct connection
            proxy_cmd = f"sshpass -p '{hop_pass}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p {hop_user}@{hop_ip}"
        else:
            # Nested hop - use previous proxy command
            prev_proxy = proxy_commands[i-1]
            proxy_cmd = f"sshpass -p '{hop_pass}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand='{prev_proxy}' -W %h:%p {hop_user}@{hop_ip}"

        proxy_commands.append(proxy_cmd)

    # Return the final proxy command (the most deeply nested one)
    return proxy_commands[-1] if proxy_commands else None

def create_ssh_tunnel(target_ip, username, password, preferred_port=None, hop_path=None):
    """Create SSH tunnel with SOCKS proxy on port 9050 (FIXED PORT) with multi-hop support"""
    global ssh_tunnels, ssh_processes, ssh_credentials, ssh_hop_paths, FIXED_SOCKS_PORT

    # IMPORTANT: Always use port 9050 for dynamic forwarding (only port that works reliably)
    local_port = FIXED_SOCKS_PORT

    # Check if tunnel already exists and is working
    if target_ip in ssh_tunnels and target_ip in ssh_processes:
        existing_port = ssh_tunnels[target_ip]
        existing_process = ssh_processes[target_ip]

        # Verify the process is still running
        if existing_process.poll() is None:  # Process is running
            # Test if the tunnel is still working
            if test_socks_proxy(existing_port, timeout=3):
                logger.info(f"Reusing existing working tunnel to {target_ip} on port {existing_port}")
                return existing_port
            else:
                logger.warning(f"Existing tunnel to {target_ip} is not responding, recreating...")
        else:
            logger.warning(f"Existing tunnel process to {target_ip} has died, recreating...")

    logger.info(f"Setting up new SSH tunnel to {target_ip} on fixed port {local_port}")

    # Kill any existing tunnel to this target
    if target_ip in ssh_processes:
        try:
            logger.info(f"Killing existing tunnel process to {target_ip}")
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
            # Check if we need multi-hop connection (use local port forward instead of ProxyCommand)
            use_local_forward = target_ip in local_port_forwards

            if use_local_forward:
                forward_port = local_port_forwards[target_ip]
                logger.info(f"Creating multi-hop SSH tunnel to {target_ip} via localhost:{forward_port} on port {local_port} (attempt {attempt + 1})")
            else:
                logger.info(f"Creating direct SSH tunnel to {target_ip} on port {local_port} (attempt {attempt + 1})")

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

            # Add port if using local forward (multi-hop)
            if use_local_forward:
                command.extend(['-p', str(forward_port)])

            # Add dynamic port forward and target (ALWAYS port 9050)
            if use_local_forward:
                # Multi-hop: connect through local forward
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

            # Log the full command with password masked
            command_str = ' '.join(command)
            masked_cmd = command_str.replace(password, '***PASSWORD***')
            logger.info(f"[SSH COMMAND] Dynamic tunnel (-D {local_port}): {masked_cmd}")

            # Start SSH process in background
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Give tunnel more time to establish (critical for reliability)
            logger.info(f"Waiting for tunnel to establish...")
            time.sleep(5)

            # Check if process is still running
            poll_result = process.poll()
            if poll_result is not None:
                # Process exited, get error output
                stdout, stderr = process.communicate()
                logger.warning(f"SSH process exited with code {poll_result}: {stderr}")
                continue

            # Test if tunnel is actually working - try multiple times
            tunnel_working = False
            for verify_attempt in range(5):  # Try 5 times
                logger.debug(f"Verifying tunnel (attempt {verify_attempt + 1}/5)...")
                if test_socks_proxy(local_port, timeout=10):
                    tunnel_working = True
                    break
                else:
                    logger.debug(f"Tunnel not ready yet, waiting...")
                    time.sleep(2)

            if tunnel_working:
                # IMPORTANT: Store process reference to keep it alive
                ssh_processes[target_ip] = process
                ssh_tunnels[target_ip] = local_port
                logger.info(f"✓ SSH tunnel established and verified to {target_ip} on port {local_port}")
                logger.info(f"✓ Tunnel process PID: {process.pid} - keeping alive for the session")
                return local_port
            else:
                logger.warning(f"SSH tunnel process running but SOCKS proxy not responding after multiple attempts")
                # Kill the process since proxy isn't working
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
            logger.info(f"Retrying tunnel creation to {target_ip} in 2 seconds...")
            time.sleep(2)
            # Re-kill port 9050 before retry
            force_kill_port_9050()

    logger.error(f"Failed to create working SSH tunnel to {target_ip} after {max_attempts} attempts")
    return None

def cleanup_port_tunnels(port):
    """Kill any existing SSH tunnels using the specified port"""
    try:
        # Kill SSH processes using this port
        subprocess.run(f"pkill -f 'ssh.*-D.*{port}'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)  # Give time for cleanup
    except:
        pass

def force_kill_port_9050():
    """Forcefully kill any process using port 9050 to free it for our dynamic forwarding"""
    try:
        logger.info("Clearing port 9050 for dynamic forwarding...")

        # Method 1: Kill by pattern matching SSH with -D 9050
        subprocess.run("pkill -9 -f 'ssh.*-D.*9050'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Method 2: Find and kill process listening on port 9050
        result = subprocess.run("lsof -ti:9050", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid:
                    logger.info(f"Killing process {pid} using port 9050")
                    subprocess.run(f"kill -9 {pid}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(2)  # Give time for port to be fully released
        logger.info("Port 9050 cleared and ready")

    except Exception as e:
        logger.warning(f"Error clearing port 9050: {e}")
        # Continue anyway, the port might already be free

def scan_through_proxy(target_ip, proxy_port, scan_range=None):
    """Scan network through SOCKS proxy using proxychains with enhanced error handling"""
    discovered_hosts = []
    
    # Test if proxy is working before attempting scan
    if not test_socks_proxy(proxy_port, timeout=5):
        logger.error(f"SOCKS proxy on port {proxy_port} is not responding, skipping scan")
        return []
    
    # Configure proxychains for this specific proxy with multiple fallback configs
    proxychains_conf = f"/tmp/proxychains_{proxy_port}.conf"

    # Create robust proxychains configuration
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

    logger.info(f"[PROXYCHAINS CONFIG] Created {proxychains_conf} with SOCKS5 proxy at 127.0.0.1:{proxy_port}")
    
    if scan_range:
        # TCP connect scan through proxy (ping sweeps don't work with proxychains)
        # Use -sT with common ports to detect live hosts
        network_base = ".".join(target_ip.split(".")[:3])
        start_range, end_range = scan_range

        # Use TCP connect scan on common ports (proxychains requirement)
        # Check ports 22,80,443,445 to detect most devices
        command = f"proxychains4 -f {proxychains_conf} nmap -sT -Pn -p 22,80,443,445,3389,8080 --open {network_base}.{start_range}-{end_range}"

        try:
            logger.info(f"TCP scanning network {network_base}.{start_range}-{end_range} through proxy (proxychains -sT)")
            logger.info(f"[PROXYCHAINS COMMAND] Network scan: {command}")
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=600)

            # Parse nmap output for discovered hosts (any host with at least one open port)
            found_ips = re.findall(r'Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result.stdout)

            # Filter to only include hosts that had open ports
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    # This line has an open port, the host is alive
                    pass  # IP already captured above

            discovered_hosts.extend(found_ips)
            logger.info(f"Found {len(found_ips)} hosts with open ports through proxy")

        except subprocess.TimeoutExpired:
            logger.warning(f"Network scan through proxy timed out for {network_base}")
        except Exception as e:
            logger.error(f"Error scanning network through proxy: {e}")
    
    return discovered_hosts

def scan_host_ports_proxy(target_ip, proxy_port):
    """Scan specific host ports through SOCKS proxy with enhanced reliability"""
    ports_info = []
    
    # Test proxy before scanning
    if not test_socks_proxy(proxy_port, timeout=5):
        logger.error(f"SOCKS proxy on port {proxy_port} is not responding, cannot scan {target_ip}")
        return [], None
    
    proxychains_conf = f"/tmp/proxychains_{proxy_port}.conf"
    
    # IMPORTANT: Only -sT (TCP connect) works with proxychains - no -sS, -sU, or ping scans
    # Wrap with shell timeout command for aggressive timeout enforcement (kills process after 10s)
    scan_commands = [
        f"timeout -k 2 10 proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 1000 {target_ip}",
        f"timeout -k 2 10 proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 500 {target_ip}",  # Fallback with fewer ports
        f"timeout -k 2 10 proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 100 {target_ip}"   # Smaller port range fallback
    ]

    # Try each scan command until one succeeds
    for i, command in enumerate(scan_commands):
        try:
            scan_type = ["TCP connect (1000 ports)", "TCP connect (500 ports)", "TCP connect (100 ports)"][i]
            logger.info(f"Port scanning {target_ip} through proxy using {scan_type} (max 10s)")
            logger.info(f"[PROXYCHAINS COMMAND] Port scan: {command}")

            # Use Popen for better process control
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True, preexec_fn=os.setsid)

            try:
                stdout, stderr = process.communicate(timeout=12)  # 12s to allow timeout command to work
                result = type('obj', (object,), {'returncode': process.returncode, 'stdout': stdout, 'stderr': stderr})()
            except subprocess.TimeoutExpired:
                # If even timeout command fails, forcefully kill the process group
                logger.warning(f"Scan forcefully killed after timeout for {target_ip} (attempt {i+1})")
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except:
                    pass
                process.kill()
                process.wait()
                if i == len(scan_commands) - 1:
                    return [], None
                continue
            
            # Exit code 124 means timeout command killed the process
            if result.returncode == 124:
                logger.warning(f"Scan timed out after 10 seconds for {target_ip} (attempt {i+1}), skipping to next method")
                if i == len(scan_commands) - 1:
                    return [], None
                continue

            if result.returncode == 0 and result.stdout:
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

                if ports_info or i == len(scan_commands) - 1:  # Return results if found or last attempt
                    logger.info(f"Successfully scanned {target_ip} through proxy, found {len(ports_info)} open ports")
                    return ports_info, mac_addr
            else:
                logger.warning(f"Scan attempt {i+1} failed for {target_ip}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Port scan timed out for {target_ip} (attempt {i+1})")
            if i == len(scan_commands) - 1:
                return [], None
        except Exception as e:
            logger.warning(f"Error port scanning {target_ip} (attempt {i+1}): {e}")
            if i == len(scan_commands) - 1:
                return [], None
    
    return [], None

def discover_network_devices(network_base, start_range, end_range, pivot_ip):
    """Enhanced network discovery using multiple methods"""
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
    
    # Method 3: DISABLED - Fallback TCP connect scan (too slow, rely on ping sweeps instead)
    # For remote networks, use ping_sweep_remote() which is much faster
    # For local networks, ping sweeps should be sufficient
    if False and len(discovered_ips) < 2:  # DISABLED: TCP scan fallback
        logger.info("Few devices found via ping, trying TCP connect scan...")
        try:
            tcp_command = f"nmap -sT -Pn --top-ports=10 --max-retries=1 --host-timeout=5s {network_base}.{start_range}-{end_range}"
            result = subprocess.run(tcp_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=180)

            # Parse TCP scan results
            current_ip = None
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    ip_match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                elif current_ip and 'open' in line and current_ip != pivot_ip and current_ip not in discovered_ips:
                    discovered_ips.append(current_ip)
                    logger.info(f"Found device via TCP connect: {current_ip}")
                    current_ip = None

        except Exception as e:
            logger.warning(f"TCP connect scan failed: {e}")
    
    logger.info(f"Network discovery complete: found {len(discovered_ips)} devices")
    return discovered_ips

def scan_host_directly(target_ip):
    """Enhanced host scanning from pivot device"""
    ports_processes = []
    found_mac = None

    # Build scan commands list based on flags
    scan_commands = [
        f"nmap -Pn -sS --top-ports 1000 {target_ip}",     # SYN scan (fastest, most ports)
        f"nmap -Pn -sT --top-ports 500 {target_ip}",      # Connect scan (more reliable)
    ]
    scan_types = ["SYN scan", "TCP connect scan"]
    timeouts = [90, 120]

    # Add UDP scan only if UDP_SCAN is enabled
    if UDP_SCAN:
        scan_commands.append(f"nmap -Pn -sU --top-ports 100 {target_ip}")  # UDP scan (for UDP services)
        scan_types.append("UDP scan")
        timeouts.append(180)  # UDP scans need more time

    for i, command in enumerate(scan_commands):
        try:
            scan_type = scan_types[i]
            logger.info(f"Port scanning {target_ip} using {scan_type}")

            timeout = timeouts[i]
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                scan_ports = []
                
                for line in lines:
                    # TCP ports
                    if '/tcp' in line and 'open' in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            port_proto = parts[0]
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            
                            if state == 'open':
                                port = port_proto.split('/')[0]
                                scan_ports.append((port, service + '/tcp'))
                    
                    # UDP ports
                    elif '/udp' in line and ('open' in line or 'open|filtered' in line):
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            port_proto = parts[0]
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            
                            if 'open' in state:
                                port = port_proto.split('/')[0]
                                scan_ports.append((port, service + '/udp'))
                    
                    # MAC Address
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
    """Recursively scan a device's networks and any SSH-accessible devices found

    Args:
        device_ip: IP of the device to scan
        username: SSH username
        password: SSH password
        hop_path: List of IPs showing the path to reach this device
        current_depth: Current recursion depth (for logging)
        max_depth: Maximum depth to prevent infinite loops
    """
    global all_info, usernames, passwords, recursively_scanned_devices

    if current_depth >= max_depth:
        logger.warning(f"Reached maximum depth ({max_depth}) at {device_ip}, stopping recursion")
        return

    logger.info(f"{'  ' * current_depth}[Depth {current_depth}] Scanning device {device_ip}")

    # Store credentials and hop path
    ssh_credentials[device_ip] = (username, password)
    ssh_hop_paths[device_ip] = hop_path

    # Extract network info from this device
    logger.info(f"{'  ' * current_depth}Extracting network info from {device_ip}")
    remote_success, remote_mac_key = extract_remote_device_info(device_ip, username, password)

    if not remote_success:
        logger.warning(f"{'  ' * current_depth}Could not extract network info from {device_ip}")
        return

    logger.info(f"{'  ' * current_depth}Successfully extracted network info from {device_ip}")

    # Create SSH tunnel to this device (SOCKS proxy for port scanning)
    logger.info(f"{'  ' * current_depth}Creating SSH tunnel to {device_ip}")
    tunnel_port = create_ssh_tunnel(device_ip, username, password, hop_path=hop_path)

    if not tunnel_port:
        logger.error(f"{'  ' * current_depth}Failed to create SSH tunnel to {device_ip}")
        return

    logger.info(f"{'  ' * current_depth}SSH tunnel established to {device_ip} on port {tunnel_port}")

    # Get the network information we extracted
    device_info = all_info[remote_mac_key]
    device_ips = device_info[1]      # Device's own IPs
    device_masks = device_info[3]    # Network masks
    device_ranges = device_info[4]   # Network ranges to scan

    logger.info(f"{'  ' * current_depth}Device has {len(device_ips)} networks to scan")

    # Scan each network discovered on this device
    time.sleep(2)  # Give tunnel time to establish

    for idx, net_ip in enumerate(device_ips):
        network_range = device_ranges[idx]
        network_mask = device_masks[idx]
        network_id = get_network_identifier(net_ip, network_mask)

        # Skip if already scanned from this device
        network_scan_key = f"{network_id}_via_mac_{remote_mac_key}"
        if is_network_already_scanned(network_scan_key):
            logger.info(f"{'  ' * current_depth}Network {network_id} already scanned from this device")
            continue

        mark_network_as_scanned(network_scan_key)

        # Run ping sweep to discover hosts
        network_base = ".".join(net_ip.split(".")[:3])
        logger.info(f"{'  ' * current_depth}Ping sweep on {network_base}.0/24 from {device_ip}")

        discovered_hosts = ping_sweep_remote(
            device_ip, username, password,
            network_base,
            network_range[0],
            network_range[1],
            exclude_ips=device_ips  # Don't scan device's own IPs
        )

        if not discovered_hosts:
            logger.info(f"{'  ' * current_depth}No hosts found on {network_id}")
            continue

        logger.info(f"{'  ' * current_depth}Found {len(discovered_hosts)} hosts on {network_id}")

        # Scan ports on each discovered host
        for host_ip in discovered_hosts:
            # Skip if this is the current device itself (defensive check)
            if host_ip == device_ip:
                logger.debug(f"{'  ' * current_depth}{host_ip} is current device, skipping")
                continue

            # Skip if this device is in our hop path (we already SSH'd through it to get here)
            if host_ip in hop_path:
                logger.debug(f"{'  ' * current_depth}{host_ip} is in hop path, skipping (already scanned)")
                continue

            # Always scan ports and add to topology (even if discovered before)
            # But skip SSH recursion if already recursively scanned
            if host_ip in recursively_scanned_devices:
                logger.debug(f"{'  ' * current_depth}{host_ip} already recursively scanned, skipping SSH attempt")
                continue

            logger.info(f"{'  ' * current_depth}Scanning ports on {host_ip}")
            host_ports, host_mac = scan_host_ports_proxy(host_ip, tunnel_port)

            # Check if device has SSH
            has_ssh = any(p[0] == '22' for p in host_ports)

            # Add to topology
            path_str = '->'.join(hop_path + [host_ip])
            add_device_to_topology(
                host_ip, host_mac, host_ports, network_id,
                path_str,
                ssh_accessible=has_ssh
            )

            # RECURSIVE: If device has SSH, scan it too!
            if has_ssh:
                logger.info(f"{'  ' * current_depth}Device {host_ip} has SSH - scanning recursively")

                # Try SSH with known credentials
                # The hop_path to reach host_ip is: hop_path + [device_ip]
                new_hop_path = hop_path + [device_ip]
                for try_user, try_pass in zip(usernames, passwords):
                    if attempt_ssh_connection(host_ip, try_user, try_pass, hop_path=new_hop_path):
                        logger.info(f"{'  ' * current_depth}SSH successful to {host_ip} via multi-hop")

                        # Mark as recursively scanned BEFORE recursing to prevent duplicate attempts
                        
                        recursively_scanned_devices.add(host_ip)

                        # RECURSE: Scan this device and its networks
                        scan_device_and_networks_recursive(
                            host_ip, try_user, try_pass,
                            new_hop_path,
                            current_depth + 1,
                            max_depth
                        )
                        break  # Stop trying credentials once successful
            else:
                logger.debug(f"{'  ' * current_depth}{host_ip} has no SSH, not scanning deeper")

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
        
        # Enhanced network discovery using multiple methods
        discovered_ips = discover_network_devices(
            first_three_octets, 
            network_range[0], 
            network_range[1], 
            pivot_ip
        )
        
        # Filter out already discovered devices
        new_devices = [ip for ip in discovered_ips if not is_device_already_discovered(ip)]

        if new_devices:
            logger.info(f"Found {len(new_devices)} new devices on network {network_id}")
            returned_dict[pivot_ip] = [new_devices, [], []]
        else:
            logger.info(f"No new devices found on network {network_id} via nmap")
            logger.info(f"Trying local ping sweep as fallback...")

            # FALLBACK: Try a local ping sweep (faster, might find devices nmap missed)
            # This runs ping commands locally instead of nmap
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
                logger.warning(f"Local ping sweep failed: {e}")
                if network_id not in returned_dict:
                    returned_dict[pivot_ip] = [[], [], []]
                continue

        # Now scan individual hosts and attempt SSH tunneling
        # current_path tracks devices we've hopped THROUGH to get here
        # Since we're scanning FROM the pivot (not through it), start with empty path
        current_path = []
        
        for discovered_ip in new_devices:
            # Check if we've already attempted SSH on this device (prevents loops)
            if discovered_ip in recursively_scanned_devices:
                logger.info(f"Device {discovered_ip} already fully scanned (SSH attempted), skipping")
                continue

            logger.info(f"Analyzing device {discovered_ip}")

            # First, scan ports on this host from pivot
            ports_info, mac_addr = scan_host_directly(discovered_ip)

            # Add device to topology (for visualization, but not marked as "fully scanned" yet)
            add_device_to_topology(
                discovered_ip, mac_addr, ports_info, network_id,
                f"pivot->{discovered_ip}",
                ssh_accessible=any(port[0] == '22' for port in ports_info)
            )

            # Try to establish SSH connection for deeper scanning
            ssh_success = False

            # Check if we should create tunnel (avoid cycles)
            logger.info(f"Checking if SSH tunnel should be created for {discovered_ip}")
            if should_create_ssh_tunnel(discovered_ip, current_path):
                logger.info(f"Attempting SSH credentials for {discovered_ip} (have {len(usernames)} credentials to try)")

                if len(usernames) == 0:
                    logger.warning("No credentials available! Check credentials.txt file")

                for username, password in zip(usernames, passwords):
                    logger.debug(f"Trying credential {username}:{'*' * len(password)}")
                    if attempt_ssh_connection(discovered_ip, username, password, hop_path=current_path):
                        logger.info(f"SSH access successful to {discovered_ip} with {username}")
                        ssh_success = True

                        # Store credentials for this device (for potential multi-hop use)
                        ssh_credentials[discovered_ip] = (username, password)

                        # Record this access path
                        ssh_access_paths[discovered_ip] = current_path + [discovered_ip]

                        # USE RECURSIVE FUNCTION: Scan this device and all its networks (unlimited depth)
                        logger.info(f"Recursively scanning {discovered_ip} and its networks")
                        try:
                            scan_device_and_networks_recursive(
                                discovered_ip, username, password,
                                hop_path=current_path,
                                current_depth=1,
                                max_depth=20  # Support up to 20 hops!
                            )
                        except Exception as e:
                            logger.error(f"Error during recursive scan of {discovered_ip}: {e}")

                        break  # Stop trying credentials once successful

                if not ssh_success:
                    logger.info(f"No valid SSH credentials found for {discovered_ip}")
            else:
                logger.info(f"SSH tunnel creation skipped for {discovered_ip} (cycle prevention or already accessible)")

            # Mark device as fully scanned AFTER SSH attempt (whether successful or not)
            # This prevents re-attempting SSH on the same device in future network scans
            recursively_scanned_devices.add(discovered_ip)
            logger.debug(f"Marked {discovered_ip} as fully scanned")

            # Note: Legacy non-recursive scanning code was removed here.
            # All network scanning is now handled by scan_device_and_networks_recursive()

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
    """Clean up SSH tunnels (all on port 9050), local port forwards, and temporary files"""
    global ssh_tunnels, ssh_processes, FIXED_SOCKS_PORT, local_port_forwards, local_forward_processes

    logger.info("Cleaning up SSH tunnels and local port forwards...")

    # First, kill tracked local port forward processes
    for target_ip, process in list(local_forward_processes.items()):
        try:
            local_port = local_port_forwards.get(target_ip, "unknown")
            logger.info(f"Terminating local port forward to {target_ip} (port {local_port}, PID: {process.pid})")
            process.terminate()
            process.wait(timeout=3)
        except:
            try:
                process.kill()
            except:
                pass

    # Kill tracked SSH tunnel processes gracefully
    for target_ip, process in list(ssh_processes.items()):
        try:
            logger.info(f"Terminating tunnel process to {target_ip} (PID: {process.pid})")
            process.terminate()
            process.wait(timeout=3)
        except:
            try:
                process.kill()
            except:
                pass

    # Kill all SSH tunnel processes on port 9050
    logger.info(f"Killing all processes using port {FIXED_SOCKS_PORT}")
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

    # Clear tracking variables
    ssh_tunnels.clear()
    ssh_processes.clear()
    ssh_credentials.clear()
    ssh_hop_paths.clear()
    local_port_forwards.clear()
    local_forward_processes.clear()

    # Give time for cleanup
    time.sleep(2)

    logger.info("SSH tunnel cleanup complete")

def save_results_to_json(results, filename="network_scan_results.json"):
    """Save scan results to JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving results: {e}")

def parse_arguments():
    """Parse command line arguments"""
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

# Main execution
if __name__ == "__main__":
    # Parse command line arguments
    args = parse_arguments()

    # Set global flags from command line arguments (declared at module level)
    UDP_SCAN = args.udp
    ARP_SCAN = args.arp

    logger.info("Starting network mapping from pivot device")
    logger.info(f"Scan options: UDP={'enabled' if UDP_SCAN else 'disabled'}, ARP={'enabled' if ARP_SCAN else 'disabled'}")

    if UDP_SCAN:
        logger.info("⚠️  UDP scanning enabled - may take significantly longer")
    if ARP_SCAN:
        logger.info("🔍 ARP table checking enabled for device discovery")
    
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






      
      
      

      
  
    

    
  