#!/usr/bin/env python3
"""
Test script to demonstrate enhanced network discovery capabilities
"""

import subprocess
import sys
import re

def test_arp_discovery():
    """Test ARP table scanning"""
    print("=== ARP Table Discovery Test ===")
    try:
        result = subprocess.run("arp -a", shell=True, capture_output=True, text=True, timeout=10)
        arp_ips = re.findall(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', result.stdout)
        
        print(f"Found {len(arp_ips)} devices in ARP table:")
        for ip in arp_ips:
            print(f"  - {ip}")
        return arp_ips
    except Exception as e:
        print(f"ARP discovery failed: {e}")
        return []

def test_nmap_discovery(network="192.168.1.0/24"):
    """Test nmap ping sweep"""
    print(f"\n=== Nmap Ping Sweep Test ({network}) ===")
    
    commands = [
        f"nmap -sn -PE -PP -PM --max-retries=1 {network}",  # ICMP ping
        f"nmap -sn -PS22,80,443 --max-retries=1 {network}",  # TCP SYN ping
        f"nmap -sn -PA80,443 --max-retries=1 {network}",     # TCP ACK ping
    ]
    
    all_ips = set()
    
    for i, command in enumerate(commands):
        scan_type = ["ICMP ping", "TCP SYN ping", "TCP ACK ping"][i]
        print(f"\nTesting {scan_type}...")
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
            ips = re.findall(r'Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result.stdout)
            
            print(f"  Found {len(ips)} devices via {scan_type}")
            for ip in ips:
                print(f"    - {ip}")
                all_ips.add(ip)
                
        except Exception as e:
            print(f"  {scan_type} failed: {e}")
    
    print(f"\nTotal unique devices found: {len(all_ips)}")
    return list(all_ips)

def test_port_discovery(target_ip):
    """Test enhanced port scanning"""
    print(f"\n=== Port Scanning Test ({target_ip}) ===")
    
    commands = [
        f"nmap -Pn -sS --top-ports 100 {target_ip}",     # SYN scan
        f"nmap -Pn -sT --top-ports 50 {target_ip}",      # Connect scan
    ]
    
    all_ports = []
    
    for i, command in enumerate(commands):
        scan_type = ["SYN scan", "TCP connect scan"][i]
        print(f"\nTesting {scan_type}...")
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
            
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        port = parts[0].split('/')[0]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        port_info = (port, service)
                        if port_info not in all_ports:
                            all_ports.append(port_info)
                            print(f"    Found: {port}/{service}")
                            
        except Exception as e:
            print(f"  {scan_type} failed: {e}")
    
    print(f"\nTotal open ports found: {len(all_ports)}")
    return all_ports

def main():
    if len(sys.argv) > 1:
        network = sys.argv[1]
    else:
        network = "192.168.1.0/24"
        print(f"Usage: {sys.argv[0]} [network_cidr]")
        print(f"Using default network: {network}")
    
    # Test ARP discovery
    arp_devices = test_arp_discovery()
    
    # Test nmap discovery
    nmap_devices = test_nmap_discovery(network)
    
    # Combine results
    all_devices = set(arp_devices + nmap_devices)
    print(f"\n=== SUMMARY ===")
    print(f"Total unique devices discovered: {len(all_devices)}")
    
    # Test port scanning on first device found
    if all_devices:
        test_target = list(all_devices)[0]
        print(f"Testing port scanning on: {test_target}")
        test_port_discovery(test_target)
    else:
        print("No devices found to test port scanning")

if __name__ == "__main__":
    main()