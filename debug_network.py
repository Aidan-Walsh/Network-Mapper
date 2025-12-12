#!/usr/bin/env python3
"""
Debug script to trace network interface detection issues
"""

import subprocess
import re
import math

def debug_ip_a():
    """Debug the 'ip a' command output parsing"""
    print("=== Debugging 'ip a' command ===")
    
    command = ["ip", "a"]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        output = "\n" + result.stdout
        print("Raw 'ip a' output:")
        print(output)
        print("-" * 50)
        
        # Show how the script parses it
        interfaces_info = re.split(r'[\n][0-9]: ', output)[1:]
        print(f"Split into {len(interfaces_info)} interface sections:")
        
        for i, info in enumerate(interfaces_info):
            print(f"\nInterface {i+1}:")
            print(f"Raw: {info[:100]}...")
            
            interface_rest = info.split(": ")
            print(f"Interface name candidate: {interface_rest[0] if interface_rest else 'None'}")
            
            if len(interface_rest) > 1:
                ether_rest = interface_rest[1].split("link/ether ")
                inet_rest = ether_rest[0].split("inet ")
                
                if len(ether_rest) > 1:
                    inet_rest = ether_rest[1].split("inet ")
                    mac = ether_rest[1].split(" ")[0] if len(ether_rest[1].split(" ")) > 0 else "No MAC"
                    print(f"MAC found: {mac}")
                
                if len(inet_rest) > 1:
                    net_rest = inet_rest[1].split(" ")
                    network = net_rest[0] if net_rest else "No network"
                    print(f"Network found: {network}")
                else:
                    print("No inet address found")
            else:
                print("Interface parsing failed")
                
    except Exception as e:
        print(f"Error running 'ip a': {e}")

def debug_private_network_detection():
    """Debug private network filtering"""
    print("\n=== Testing Private Network Detection ===")
    
    test_networks = [
        "10.5.0.1/24",
        "10.5.0.1/8", 
        "10.5.0.1/16",
        "192.168.1.100/24",
        "172.16.1.50/16",
        "8.8.8.8/32"  # Should be filtered out
    ]
    
    for network in test_networks:
        ip_part = network.split('/')[0]
        octets = ip_part.split('.')
        
        if len(octets) >= 2:
            first_octet = int(octets[0])
            second_octet = int(octets[1]) if len(octets) > 1 else 0
            
            is_private = (first_octet == 10 or 
                         (first_octet == 172 and 16 <= second_octet <= 31) or 
                         (first_octet == 192 and second_octet == 168))
            
            print(f"{network}: {'PRIVATE' if is_private else 'PUBLIC'}")

def debug_network_range_calculation():
    """Debug network range calculation"""
    print("\n=== Testing Network Range Calculation ===")
    
    test_cases = [
        ("10.5.0.1", "24"),
        ("10.5.0.1", "8"),
        ("10.5.0.1", "16"),
        ("192.168.1.100", "24"),
        ("172.16.5.10", "16")
    ]
    
    for ip, mask in test_cases:
        print(f"\nTesting {ip}/{mask}:")
        
        try:
            mask_int = int(mask)
            octets = ip.split(".")
            last_octet = int(octets[3])
            
            # Calculate network size and range
            host_bits = 32 - mask_int
            network_size = 2 ** host_bits
            
            print(f"  Host bits: {host_bits}, Network size: {network_size}")
            
            if mask_int == 24:
                first_device = 1
                last_device = 254
            else:
                network_start = (last_octet // network_size) * network_size
                first_device = network_start + 1
                last_device = network_start + network_size - 2
                
                first_device = max(1, min(first_device, 254))
                last_device = max(first_device, min(last_device, 254))
            
            print(f"  Calculated range: {first_device}-{last_device}")
            
        except Exception as e:
            print(f"  Error: {e}")

def debug_discovery_commands():
    """Show what discovery commands would be run"""
    print("\n=== Testing Discovery Commands ===")
    
    network_base = "10.5.0"
    start_range = 1
    end_range = 254
    
    print(f"For network {network_base}.{start_range}-{end_range}:")
    
    # ARP scan
    print("\n1. ARP scan:")
    try:
        result = subprocess.run("arp -a", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
        arp_ips = re.findall(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', result.stdout)
        print(f"   Raw ARP output:\n{result.stdout}")
        print(f"   Found IPs: {arp_ips}")
        
        for ip in arp_ips:
            octets = ip.split('.')
            if (octets[0] + '.' + octets[1] + '.' + octets[2]) == network_base:
                print(f"   → {ip} matches our network!")
                
    except Exception as e:
        print(f"   ARP scan failed: {e}")
    
    # Nmap commands
    network_cidr = f"{network_base}.0/24"
    print(f"\n2. Nmap commands for {network_cidr}:")
    
    commands = [
        f"nmap -sn -PE -PP -PM --max-retries=2 {network_cidr}",
        f"nmap -sn -PS22,80,443 --max-retries=2 {network_cidr}",
        f"nmap -sn -PA80,443 --max-retries=2 {network_cidr}",
    ]
    
    for cmd in commands:
        print(f"   {cmd}")

def main():
    print("Network Discovery Debug Tool")
    print("=" * 50)
    
    debug_ip_a()
    debug_private_network_detection()
    debug_network_range_calculation()
    debug_discovery_commands()
    
    print(f"\n=== Quick Manual Test ===")
    print("Try these commands manually to see if they work:")
    print("1. ping -c 1 10.5.0.2")
    print("2. nmap -sn 10.5.0.2")
    print("3. nmap -sn 10.5.0.0/24")
    print("4. arp -a | grep 10.5.0")

if __name__ == "__main__":
    main()