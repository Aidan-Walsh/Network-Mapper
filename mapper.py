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
from concurrent.futures import ThreadPoolExecutor, as_completed






# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variables for command line options
UDP_SCAN = False  # Default: no UDP scanning (slow)
ARP_SCAN = False  # Default: no ARP table checking

# Global variables for SSH tunneling and cycle detection
ssh_tunnels = {}  # Track active SSH tunnels: {ip: port}
tunnel_counter = 8000  # Starting port for SOCKS proxies
used_ports = set()  # Track used local ports to avoid conflicts
ssh_credentials = {}  # Track SSH credentials for each device: {ip: (username, password)}
ssh_hop_paths = {}  # Track the hop path to reach each device: {ip: [hop1_ip, hop2_ip, ...]}

# Common SOCKS proxy ports for fallback
SOCKS_PORT_CANDIDATES = [
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,  # Starting range
    9050, 9051, 9052, 9053, 9054,  # Tor default ports
    1080, 1081, 1082, 1083, 1084,  # Standard SOCKS ports
    8080, 8081, 8082, 8888,        # HTTP proxy ports (can work for SOCKS)
    3128, 3129, 3130,              # Squid proxy ports
    1337, 1338, 1339,              # Alternative ports
    9999, 9998, 9997               # High number fallbacks
]
discovered_devices = set()  # Track all discovered device IPs to prevent duplicates
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
    
    mac_key = "".join(macs)
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

def attempt_ssh_connection(target_ip, username, password):
    """Test if SSH connection is possible to a target"""
    test_command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 {username}@{target_ip} 'echo connected'"

    try:
        result = subprocess.run(test_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15)
        return result.returncode == 0
    except:
        return False

def execute_remote_command(target_ip, username, password, command, timeout=30):
    """Execute a command on a remote device via SSH (supports multi-hop) and return the output"""
    # Build ProxyCommand chain if needed for multi-hop
    proxy_command = build_proxy_command_chain(target_ip)

    if proxy_command:
        logger.debug(f"Executing remote command on {target_ip} via multi-hop")
        ssh_command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ProxyCommand='{proxy_command}' {username}@{target_ip} '{command}'"
    else:
        logger.debug(f"Executing remote command on {target_ip} (direct)")
        ssh_command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 {username}@{target_ip} '{command}'"

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
    mac_key = "".join(returned_macs)
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
    try:
        import socks
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", port)
        s.settimeout(timeout)
        # Try to connect to a known good address
        s.connect(("8.8.8.8", 53))  # Google DNS
        s.close()
        return True
    except:
        # Fallback test using curl if socks module not available
        try:
            test_cmd = f"timeout {timeout} curl -x socks5://127.0.0.1:{port} -s http://www.google.com --max-time {timeout}"
            result = subprocess.run(test_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout+2)
            return result.returncode == 0
        except:
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
    """Create SSH tunnel with SOCKS proxy using sshpass with multi-hop support"""
    global ssh_tunnels, used_ports, ssh_credentials, ssh_hop_paths
    
    # If target already has a working tunnel, return existing port
    if target_ip in ssh_tunnels:
        existing_port = ssh_tunnels[target_ip]
        if test_socks_proxy(existing_port, timeout=5):
            logger.info(f"Reusing existing SSH tunnel to {target_ip} on port {existing_port}")
            return existing_port
        else:
            logger.warning(f"Existing tunnel to {target_ip} on port {existing_port} not responding, creating new tunnel")
            # Remove failed tunnel info
            del ssh_tunnels[target_ip]
            if existing_port in used_ports:
                used_ports.remove(existing_port)
    
    # Try to get an available port
    local_port = preferred_port if preferred_port and is_port_available(preferred_port) else get_available_port()
    
    if not local_port:
        logger.error(f"No available ports for SSH tunnel to {target_ip}")
        return None
    
    # First kill any existing SSH tunnels on this port
    cleanup_port_tunnels(local_port)
    
    # Store credentials for potential multi-hop use
    ssh_credentials[target_ip] = (username, password)
    if hop_path:
        ssh_hop_paths[target_ip] = hop_path

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            # Check if we need multi-hop connection
            proxy_command = build_proxy_command_chain(target_ip)

            if proxy_command:
                logger.info(f"Creating multi-hop SSH tunnel to {target_ip} via {ssh_hop_paths[target_ip]} on port {local_port} (attempt {attempt + 1})")
            else:
                logger.info(f"Creating direct SSH tunnel to {target_ip} on port {local_port} (attempt {attempt + 1})")

            # Create SSH tunnel command without -f flag to avoid hanging
            # Use Popen for better process control
            command = [
                'sshpass', '-p', password,
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ExitOnForwardFailure=yes',
                '-o', 'ConnectTimeout=10',
                '-o', 'ServerAliveInterval=30'
            ]

            # Add ProxyCommand if multi-hop connection is needed
            if proxy_command:
                command.extend(['-o', f'ProxyCommand={proxy_command}'])

            # Add dynamic port forward and target
            command.extend([
                '-D', str(local_port),
                '-N',  # No remote command
                f'{username}@{target_ip}'
            ])

            logger.debug(f"SSH command: {' '.join(command)}")
            
            # Start SSH process in background
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Give tunnel time to establish (reduced from 2 to avoid hanging)
            time.sleep(3)
            
            # Check if process is still running
            poll_result = process.poll()
            if poll_result is not None:
                # Process exited, get error output
                stdout, stderr = process.communicate()
                logger.warning(f"SSH process exited with code {poll_result}: {stderr}")
                cleanup_port_tunnels(local_port)
                continue
            
            # Test if tunnel is actually working
            if test_socks_proxy(local_port, timeout=8):
                ssh_tunnels[target_ip] = local_port
                logger.info(f"SSH tunnel established and tested to {target_ip} on port {local_port}")
                return local_port
            else:
                logger.warning(f"SSH tunnel process running but SOCKS proxy not responding on port {local_port}")
                # Kill the process since proxy isn't working
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except:
                    try:
                        process.kill()
                    except:
                        pass
                cleanup_port_tunnels(local_port)
                
        except Exception as e:
            logger.warning(f"Error creating SSH tunnel to {target_ip} on port {local_port}: {e}")
            cleanup_port_tunnels(local_port)
        
        # If this attempt failed, try a different port for next attempt
        if attempt < max_attempts - 1:
            used_ports.discard(local_port)  # Free up the failed port
            local_port = get_available_port()
            if not local_port:
                break
    
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
    scan_commands = [
        f"proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 1000 {target_ip}",
        f"proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 500 {target_ip}",  # Fallback with fewer ports
        f"proxychains4 -f {proxychains_conf} nmap -Pn -sT --top-ports 100 {target_ip}"   # Smaller port range fallback
    ]

    # Try each scan command until one succeeds
    for i, command in enumerate(scan_commands):
        try:
            scan_type = ["TCP connect (1000 ports)", "TCP connect (500 ports)", "TCP connect (100 ports)"][i]
            logger.info(f"Port scanning {target_ip} through proxy using {scan_type}")
            
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=180)
            
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
    
    # Method 3: Fallback TCP connect scan to common ports (for networks that block ICMP)
    if len(discovered_ips) < 2:  # If we didn't find many devices, try TCP connect
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
            logger.info(f"No new devices found on network {network_id}")
            if network_id not in returned_dict:
                returned_dict[pivot_ip] = [[], [], []]
            continue
    
        # Now scan individual hosts and attempt SSH tunneling
        current_path = [pivot_ip]  # Track path to prevent cycles
        
        for discovered_ip in new_devices:
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
                        ssh_success = True

                        # Store credentials for this device (for potential multi-hop use)
                        ssh_credentials[discovered_ip] = (username, password)

                        # Record this access path
                        ssh_access_paths[discovered_ip] = current_path + [discovered_ip]

                        # IMPORTANT: SSH into the device and extract its network information
                        logger.info(f"Extracting network info from remote device {discovered_ip}")
                        remote_success, remote_mac_key = extract_remote_device_info(discovered_ip, username, password)

                        if remote_success:
                            logger.info(f"Successfully extracted network info from {discovered_ip}")

                            # Now create SSH tunnel to scan through this device
                            logger.info(f"Creating SSH tunnel to {discovered_ip} for network scanning")
                            active_tunnel_port = create_ssh_tunnel(discovered_ip, username, password)

                            if active_tunnel_port:
                                logger.info(f"SSH tunnel established on port {active_tunnel_port}")

                                # Get the network information we just extracted from the remote device
                                remote_device_info = all_info[remote_mac_key]
                                remote_ips = remote_device_info[1]      # Device IPs on remote device
                                remote_masks = remote_device_info[3]    # Network masks
                                remote_ranges = remote_device_info[4]   # Network ranges to scan

                                logger.info(f"Remote device has {len(remote_ips)} networks to scan through tunnel")

                                # Scan each network discovered on the remote device THROUGH the proxy tunnel
                                try:
                                    time.sleep(2)  # Give tunnel time to establish

                                    for idx, remote_net_ip in enumerate(remote_ips):
                                        remote_network_range = remote_ranges[idx]
                                        remote_mask = remote_masks[idx]
                                        remote_network_id = get_network_identifier(remote_net_ip, remote_mask)

                                        # Skip if already scanned
                                        if is_network_already_scanned(f"{remote_network_id}_via_{discovered_ip}"):
                                            logger.info(f"Network {remote_network_id} already scanned through {discovered_ip}")
                                            continue

                                        mark_network_as_scanned(f"{remote_network_id}_via_{discovered_ip}")

                                        logger.info(f"Scanning network {remote_network_id} through proxy on port {active_tunnel_port}")

                                        # Scan through the proxy tunnel
                                        deeper_hosts = scan_through_proxy(remote_net_ip, active_tunnel_port, remote_network_range)

                                        if deeper_hosts:
                                            logger.info(f"Found {len(deeper_hosts)} devices on {remote_network_id} through {discovered_ip}")

                                            # Scan ports on each discovered host
                                            for deep_host in deeper_hosts:
                                                if not is_device_already_discovered(deep_host):
                                                    deep_ports, deep_mac = scan_host_ports_proxy(deep_host, active_tunnel_port)

                                                    # Check if this device has SSH open
                                                    deep_has_ssh = any(p[0] == '22' for p in deep_ports)

                                                    # Add to topology
                                                    add_device_to_topology(
                                                        deep_host, deep_mac, deep_ports, remote_network_id,
                                                        f"pivot->{discovered_ip}->{deep_host}",
                                                        ssh_accessible=deep_has_ssh
                                                    )

                                                    # Update returned data structure
                                                    if discovered_ip not in returned_dict:
                                                        returned_dict[discovered_ip] = [[], [], []]
                                                    returned_dict[discovered_ip][0].append(deep_host)
                                                    returned_dict[discovered_ip][1].append(deep_mac)
                                                    returned_dict[discovered_ip][2].append(deep_ports)

                                                    logger.info(f"Added device {deep_host} discovered through {discovered_ip}")

                                                    # If device has SSH, try multi-hop connection to discover even deeper networks
                                                    if deep_has_ssh:
                                                        logger.info(f"Device {deep_host} has SSH, attempting multi-hop connection through {discovered_ip}")

                                                        # Set up hop path for multi-hop connection
                                                        deep_hop_path = current_path + [discovered_ip]
                                                        ssh_hop_paths[deep_host] = deep_hop_path

                                                        # Try to SSH into this deeper device
                                                        for deep_user, deep_pass in zip(usernames, passwords):
                                                            if attempt_ssh_connection(deep_host, deep_user, deep_pass):
                                                                logger.info(f"Multi-hop SSH successful to {deep_host} via {deep_hop_path}")

                                                                # Store credentials
                                                                ssh_credentials[deep_host] = (deep_user, deep_pass)

                                                                # Extract network info from this deeper device
                                                                deep_remote_success, deep_remote_mac_key = extract_remote_device_info(deep_host, deep_user, deep_pass)

                                                                if deep_remote_success:
                                                                    logger.info(f"Successfully extracted network info from multi-hop device {deep_host}")

                                                                    # Create multi-hop tunnel to scan its networks
                                                                    deep_tunnel_port = create_ssh_tunnel(deep_host, deep_user, deep_pass, hop_path=deep_hop_path)

                                                                    if deep_tunnel_port:
                                                                        logger.info(f"Multi-hop tunnel established to {deep_host} on port {deep_tunnel_port}")

                                                                        # Get networks from this deeper device
                                                                        deep_device_info = all_info[deep_remote_mac_key]
                                                                        deep_ips = deep_device_info[1]
                                                                        deep_masks = deep_device_info[3]
                                                                        deep_ranges = deep_device_info[4]

                                                                        # Scan networks through this multi-hop tunnel
                                                                        for deep_idx, deep_net_ip in enumerate(deep_ips):
                                                                            deep_net_range = deep_ranges[deep_idx]
                                                                            deep_net_mask = deep_masks[deep_idx]
                                                                            deep_net_id = get_network_identifier(deep_net_ip, deep_net_mask)

                                                                            if not is_network_already_scanned(f"{deep_net_id}_via_{deep_host}"):
                                                                                mark_network_as_scanned(f"{deep_net_id}_via_{deep_host}")
                                                                                logger.info(f"Scanning {deep_net_id} through multi-hop tunnel to {deep_host}")

                                                                                # Scan through multi-hop proxy
                                                                                even_deeper_hosts = scan_through_proxy(deep_net_ip, deep_tunnel_port, deep_net_range)

                                                                                if even_deeper_hosts:
                                                                                    logger.info(f"Found {len(even_deeper_hosts)} devices through multi-hop to {deep_host}")
                                                                                    # Add these to the topology (stopping at 3 hops for now)
                                                                                    for even_deeper in even_deeper_hosts:
                                                                                        if not is_device_already_discovered(even_deeper):
                                                                                            ed_ports, ed_mac = scan_host_ports_proxy(even_deeper, deep_tunnel_port)
                                                                                            add_device_to_topology(
                                                                                                even_deeper, ed_mac, ed_ports, deep_net_id,
                                                                                                f"pivot->{discovered_ip}->{deep_host}->{even_deeper}",
                                                                                                ssh_accessible=any(p[0] == '22' for p in ed_ports)
                                                                                            )

                                                                break  # Stop trying credentials once successful

                                except Exception as e:
                                    logger.error(f"Error scanning networks through {discovered_ip}: {e}")
                            else:
                                logger.error(f"Failed to create SSH tunnel to {discovered_ip}")
                        else:
                            logger.warning(f"Could not extract network info from {discovered_ip}, will use tunnel scanning as fallback")

                            # Fallback: Create SSH tunnel and scan through proxy
                            active_tunnel_port = create_ssh_tunnel(discovered_ip, username, password)

                            if active_tunnel_port:
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
    global ssh_tunnels, used_ports
    
    logger.info("Cleaning up SSH tunnels...")
    
    # Kill SSH tunnel processes for known ports
    for target_ip, port in ssh_tunnels.items():
        try:
            logger.info(f"Cleaning up tunnel to {target_ip} on port {port}")
            subprocess.run(f"pkill -f 'ssh.*-D.*{port}.*{target_ip}'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except:
            pass
    
    # Kill any remaining SSH tunnel processes
    try:
        subprocess.run("pkill -f 'ssh.*-D.*-f.*-N'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    used_ports.clear()
    
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






      
      
      

      
  
    

    
  