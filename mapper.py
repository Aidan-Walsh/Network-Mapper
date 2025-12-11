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

# Global variables for SSH tunneling
ssh_tunnels = {}  # Track active SSH tunnels
tunnel_counter = 8000  # Starting port for SOCKS proxies

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

  
# scan the internal network for devices, and scan their ports
# return dictionary of key = value: source ip = [[found_ips],[found_macs], [(ports,service)]]
def scan_network(joined_macs):
  global all_info
  ranges = all_info[joined_macs][4]
  ips = all_info[joined_macs][1]
  #macs = all_info[joined_macs][2]
  other_ips = []
  returned_dict = dict()
  for index in range(len(ips)):
    first_three_octets = ips[index].split(".")[:3]
    first_three_octets = ".".join(first_three_octets)

    command = "./scanner.sh " + first_three_octets + " " + str(ranges[index][0]) + " " + str(ranges[index][1])
    try:
              print(command)
              result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
              output = result.stdout.read().decode('utf-8')
              found_ips = re.findall(r'\((.*?)\)', output)
           
              for ip in found_ips:
                if ip != ips[index]:
                  other_ips.append(ip)
              print(other_ips)
              returned_dict[ips[index]] = [other_ips]
       
             
            
    except Exception as e:
              print(f"An error occurred: {e}")   
              
    
    # now scan those individual other_ips for their open ports
    for ip in other_ips:
      command = "nmap -Pn " + ip + " | grep -E \"open|MAC\""
      try:
                result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
                output = result.stdout.read().decode('utf-8').split("\n")[:-1]
                print(output)
                count = 0
                ports_processes = []
                found_macs = []
                for line in output:
                  print(line)
                  results = line.split()
                  if count != len(output) - 1:
                    print("1")
                    port = results[0].split("/")[0]
                    print(results)
                    process = results[2]
                    ports_processes.append((port,process))
                  else: 

                    mac = results[2]
                    found_macs.append(mac)
                  count += 1
               
                returned_dict[ips[index]].append(found_macs)
                returned_dict[ips[index]].append(ports_processes)
                
      
                  
                  
        
              
              
      except Exception as e:
                print(f"An error occurred: {e}")   
  print(returned_dict)
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
    """Generate ASCII art network topology for headless systems"""
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
    
    # Add legend
    ascii_map.append("")
    if use_unicode:
        ascii_map.append("╔═══ LEGEND ═══════════════════════════════════════════════╗")
        ascii_map.append("║ 🖥️  Pivot Device    🌐 Network Segment                  ║")
        ascii_map.append("║ 🔑 SSH Accessible   🔒 No SSH Access                   ║") 
        ascii_map.append("║ 📍 IP Addresses     🔓 Open Ports                      ║")
        ascii_map.append("╚══════════════════════════════════════════════════════════╝")
    else:
        ascii_map.append("+== LEGEND ===============================================+")
        ascii_map.append("| [P] Pivot Device    [N] Network Segment                |")
        ascii_map.append("| [SSH] SSH Access    [---] No SSH Access                |") 
        ascii_map.append("| Shows IP Addresses, MAC, and Open Ports                |")
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
            'pivot': '#FF6B6B',      # Red for pivot
            'accessible': '#4ECDC4',  # Teal for SSH accessible
            'discovered': '#45B7D1',  # Blue for discovered only
            'network': '#96CEB4'      # Green for network segments
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
        for source_ip, discoveries in discovered_networks.items():
            found_ips, found_macs, found_ports = discoveries
            
            # Add network segment node
            network_segment = f"Network {'.'.join(source_ip.split('.')[:3])}.x"
            G.add_node(network_segment, type='network')
            G.add_edge(pivot_name, network_segment)
            
            # Add discovered devices
            for i, ip in enumerate(found_ips):
                device_name = f"Device_{ip.replace('.', '_')}"
                mac = found_macs[i] if i < len(found_macs) and found_macs[i] else "Unknown"
                ports = found_ports[i] if i < len(found_ports) else []
                
                # Determine if device is SSH accessible (has port 22 open)
                is_ssh_accessible = any(port[0] == '22' for port in ports) if ports else False
                device_type = 'accessible' if is_ssh_accessible else 'discovered'
                
                G.add_node(device_name,
                          type=device_type,
                          ip=ip,
                          mac=mac,
                          ports=ports)
                
                G.add_edge(network_segment, device_name)
        
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
            else:
                size = 600
                shape = 'o'
            
            nx.draw_networkx_nodes(G, pos, nodelist=[node], 
                                 node_color=color, node_size=size, 
                                 node_shape=shape, alpha=0.8)
        
        # Draw edges
        nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, 
                              arrowsize=20, arrowstyle='->', alpha=0.6)
        
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
            patches.Patch(color=colors['discovered'], label='Discovered Device')
        ]
        
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
            
            # Save results
            results = {
                "device_info": all_info,
                "discovered_networks": found_devices,
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






      
      
      

      
  
    

    
  