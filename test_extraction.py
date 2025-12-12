#!/usr/bin/env python3
"""
Test script to validate network extraction for 10.5.0.x networks
"""

import subprocess
import re
import logging

# Set up logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
        print("Raw 'ip a' output:")
        print("="*50)
        print(output)
        print("="*50)
        
        # Parse each interface block
        interface_blocks = re.split(r'\n(?=\d+:)', output)
        
        print(f"\nFound {len(interface_blocks)} interface blocks:")
        
        for i, block in enumerate(interface_blocks):
            if not block.strip():
                continue
                
            print(f"\n--- Block {i} ---")
            print(block[:200] + "..." if len(block) > 200 else block)
            
            lines = block.strip().split('\n')
            if not lines:
                continue
            
            # Extract interface name from first line
            first_line = lines[0]
            interface_match = re.match(r'\d+:\s*([^:@]+)', first_line)
            if not interface_match:
                print("  → No interface name found")
                continue
                
            interface_name = interface_match.group(1).strip()
            print(f"  → Interface: {interface_name}")
            
            # Skip loopback and inactive interfaces
            if interface_name == 'lo':
                print("  → Skipping loopback")
                continue
            if 'DOWN' in first_line:
                print("  → Skipping inactive interface")
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
                    print(f"  → Found IP: {network}")
                
                # Look for MAC address
                mac_match = re.search(r'link/ether\s+([0-9a-f:]{17})', line, re.IGNORECASE)
                if mac_match and not interface_mac:
                    interface_mac = mac_match.group(1)
                    print(f"  → Found MAC: {interface_mac}")
            
            # Add each network found on this interface
            for network in interface_networks:
                interfaces.append(interface_name)
                networks.append(network)
                macs.append(interface_mac if interface_mac else "unknown")
        
        print(f"\n=== EXTRACTION RESULTS ===")
        print(f"Found {len(networks)} networks:")
        for i, (iface, net, mac) in enumerate(zip(interfaces, networks, macs)):
            print(f"  {i+1}. {iface}: {net} (MAC: {mac})")
            
        return networks, interfaces, macs
        
    except Exception as e:
        print(f"Error extracting networks: {e}")
        return [], [], []

def extract_private(networks, interfaces, macs):
    """Filter for private networks (RFC 1918) with proper parsing"""
    returned_networks = []
    returned_interfaces = []
    returned_macs = []
    
    print(f"\n=== PRIVATE NETWORK FILTERING ===")
    print(f"Testing {len(networks)} networks:")
    
    for index in range(len(networks)):
        network = networks[index]
        interface = interfaces[index]
        mac = macs[index]
        
        try:
            # Split IP from CIDR notation (e.g., "10.5.0.1/24" -> "10.5.0.1")
            ip_part = network.split("/")[0]
            octets = ip_part.split(".")
            
            print(f"  Testing {network}: IP={ip_part}, octets={octets}")
            
            if len(octets) >= 2:
                first_octet = int(octets[0])
                second_octet = int(octets[1])
                
                print(f"    First octet: {first_octet}, Second octet: {second_octet}")
                
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
                    print(f"    ✓ PRIVATE: Added {network} on {interface}")
                else:
                    print(f"    ✗ PUBLIC: Skipping {network}")
            else:
                print(f"    ✗ INVALID: Not enough octets in {network}")
                
        except (ValueError, IndexError) as e:
            print(f"    ✗ ERROR: {network}: {e}")
    
    print(f"\nFinal result: {len(returned_networks)} private networks")
    return returned_networks, returned_interfaces, returned_macs

def test_discovery_for_10_5_0():
    """Test if we can discover 10.5.0.2"""
    print(f"\n=== TESTING DISCOVERY FOR 10.5.0.2 ===")
    
    commands = [
        "ping -c 1 10.5.0.2",
        "nmap -sn 10.5.0.2", 
        "nmap -sn 10.5.0.0/24",
        "arp -a | grep 10.5.0"
    ]
    
    for cmd in commands:
        print(f"\nTesting: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
            print(f"Return code: {result.returncode}")
            if result.stdout:
                print(f"STDOUT:\n{result.stdout}")
            if result.stderr:
                print(f"STDERR:\n{result.stderr}")
        except Exception as e:
            print(f"Error: {e}")

def main():
    print("Network Extraction Test for 10.5.0.x")
    print("="*50)
    
    # Test network extraction
    all_networks, all_interfaces, all_macs = extract_networks()
    
    if not all_networks:
        print("ERROR: No networks extracted!")
        return
    
    # Test private filtering
    private_networks, private_interfaces, private_macs = extract_private(all_networks, all_interfaces, all_macs)
    
    if not private_networks:
        print("ERROR: No private networks found!")
        return
    
    # Look specifically for 10.5.0.x networks
    found_10_5_0 = False
    for network in private_networks:
        if network.startswith("10.5.0."):
            found_10_5_0 = True
            print(f"\n✓ Found target network: {network}")
            break
    
    if not found_10_5_0:
        print("\n✗ No 10.5.0.x network found in private networks!")
        print("This explains why your 10.5.0.2 device isn't being discovered.")
    
    # Test basic discovery
    test_discovery_for_10_5_0()

if __name__ == "__main__":
    main()