# Network Mapper
## Automated Network Discovery and Mapping Tool with SSH Tunneling

An advanced network mapping tool that automatically discovers and maps private network topology using SSH tunneling for deeper network penetration. The tool starts from a pivot device and systematically discovers devices, open ports, and services across multiple network segments.

## Features

- **Automatic Private Network Detection**: Identifies private networks (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- **SSH Tunneling**: Creates SOCKS proxies through discovered devices for deeper network access
- **Proxychains Integration**: Uses proxychains with nmap for scanning through SSH tunnels
- **Network Topology Visualization**: Generates visual network maps showing device relationships
- **Comprehensive Port Scanning**: Discovers open ports and running services
- **Credential-based Pivoting**: Automatically attempts SSH connections using provided credentials
- **Cycle Detection and Deduplication**: Prevents infinite loops and duplicate scanning
- **Cross-Network Device Identification**: Detects devices accessible from multiple networks
- **Shortest Path SSH Tunneling**: Avoids redundant tunnels through cycle detection
- **Progress Logging**: Detailed logging of all operations and discoveries
- **Multiple Output Formats**: JSON data export and detailed text reports

## Architecture

```
Pivot Device (nmap installed)
    |
    ├── Network Segment 1 (Direct scan)
    │   ├── Device A [SSH accessible] ──→ SSH Tunnel ──→ Deeper Network 1
    │   └── Device B [Port scan only]
    |
    └── Network Segment 2 (Direct scan)  
        ├── Device C [SSH accessible] ──→ SSH Tunnel ──→ Deeper Network 2
        └── Device D [Port scan only]
```

## Prerequisites

- Python 3.6+
- nmap (only required on pivot device)
- sshpass
- proxychains4
- sudo access on pivot device

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Network-Mapper
```

2. Run the setup script:
```bash
./setup.sh
```

This will install all required dependencies and configure the environment.

## Configuration

1. Edit `credentials.txt` with target device credentials:
```
username1:password1
username2:password2
admin:admin123
```

2. Ensure you have sudo privileges on the pivot device

## Usage

```bash
# Run as sudo for network scanning capabilities
sudo python3 mapper.py
```

The tool will:
1. Enumerate local network interfaces and private networks
2. Perform initial network discovery from pivot device
3. Attempt SSH connections to discovered devices using provided credentials
4. Create SSH tunnels through accessible devices
5. Scan deeper networks through established tunnels
6. Generate comprehensive network map and reports

## Output Files

### Always Generated:
- `network_topology_ascii.txt` - ASCII art network topology map (works in all environments)
- `network_scan_results.json` - Complete scan data in JSON format
- `network_details.txt` - Human-readable detailed report
- Real-time ASCII network map displayed in console
- Logging output to console with timestamps


### Headless/Terminal-Only Support:
The tool automatically detects headless environments and provides full functionality without GUI dependencies:
- All scanning and SSH tunneling functionality works unchanged
- Complete text-based reports and JSON data export

## Security Considerations

**WARNING**: This tool is designed for authorized security testing only.

- Only use on networks you own or have explicit permission to test
- Ensure proper authorization before running scans
- Be aware that SSH tunneling may trigger security alerts
- Tool creates temporary files that are cleaned up automatically
- All credentials are used for legitimate security assessment purposes



## Troubleshooting

1. **Permission Denied**: Ensure script is run with sudo
2. **Dependencies Missing**: Run `./setup.sh` to install requirements. Being super user may not work
3. **SSH Timeout**: Check credentials and network connectivity
4. **Port Conflicts**: 
   - Tool automatically finds available ports, but if all ports are busy:
   - Kill existing SSH tunnels: `pkill -f 'ssh.*-D'`
5. **Proxychains Issues**:
   - Ensure proxychains4 is installed: `apt install proxychains4` or `brew install proxychains-ng`
   - Check if SOCKS proxy is responding: Tool includes automatic health checks
   - Try manual test: `proxychains4 curl http://www.google.com`
6. **Tunnel Creation Failures**:
   - Check SSH key conflicts: Tool uses password authentication
   - Verify target SSH service is running: `nmap -p 22 target_ip`
   - Check firewall rules allowing outbound SSH connections

## Technical Details

The tool operates in phases:
1. **Local Enumeration**: Discover pivot device network configuration
2. **Enhanced Network Discovery**: Multi-method device discovery from pivot
3. **Cycle Detection**: Check for already-scanned networks and devices
4. **Comprehensive Port Scanning**: TCP/UDP port discovery with multiple techniques
5. **Credential Testing**: Attempt SSH access to discovered devices
6. **Path Analysis**: Determine shortest SSH paths to avoid redundant tunnels
7. **Tunnel Creation**: Establish SOCKS proxies through optimal SSH paths
8. **Deep Scanning**: Scan additional networks through tunnels with deduplication
9. **Topology Analysis**: Identify cross-network connections and potential cycles
10. **Visualization**: Generate network topology maps showing cycles and connections

**Enhanced Network Discovery Methods:**
1. **ARP Table Scanning**: Fastest method for local network devices
2. **ICMP Ping Sweep**: Traditional ping discovery (nmap -sn -PE -PP -PM)
3. **TCP SYN Ping**: Discovery via TCP SYN to ports 22, 80, 443
4. **TCP ACK Ping**: Discovery via TCP ACK to ports 80, 443
5. **UDP Ping**: Discovery via UDP to ports 53, 67, 68, 161
6. **TCP Connect Fallback**: Port-based discovery for ICMP-filtered networks

**Enhanced Port Scanning Techniques:**
1. **TCP SYN Scan**: Fast stealth scanning of top 1000 ports
2. **TCP Connect Scan**: Reliable full connection scanning of top 500 ports
3. **UDP Scan**: Discovery of UDP services on top 100 ports
4. **Multiple Retry Logic**: Automatic fallback between scan types
5. **MAC Address Discovery**: Hardware identification where possible

**Cycle Detection Features:**
- **Network Deduplication**: Prevents re-scanning the same network ranges
- **Device Deduplication**: Tracks discovered devices globally to avoid duplicates  
- **Path Optimization**: Uses shortest paths for SSH tunneling
- **Cross-Network Detection**: Identifies devices accessible from multiple networks
- **Infinite Loop Prevention**: Stops cycles in SSH tunnel chains

**SSH Tunnel Port Management:**
- **Dynamic Port**: Uses port 9050
- **Port Conflict Resolution**: Detects and avoids already-used ports
- **Tunnel Health Checking**: Tests SOCKS proxy functionality before use
- **Automatic Retry**: Attempts multiple ports if initial tunnel creation fails
- **Graceful Cleanup**: Properly terminates tunnels and frees ports on exit

Testing for this program was conducted on manually configured linux machines that were used in a controlled and isolated network environment. 


