# Network Mapper
## Automated Network Discovery and Mapping Tool with SSH Tunneling

An advanced network mapping tool that automatically discovers and maps private network topology using SSH tunneling for deeper network penetration. The tool starts from a pivot device and systematically discovers devices, open ports, and services across multiple network segments.

## Features

- **Automatic Private Network Detection**: Identifies RFC 1918 private networks (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
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

### Generated in GUI Environments:
- `network_topology.png` - Graphical network topology map (requires GUI/X11)

### Headless/Terminal-Only Support:
The tool automatically detects headless environments and provides full functionality without GUI dependencies:
- ✅ ASCII art network maps with Unicode box drawing (when supported)
- ✅ Fallback to basic ASCII characters for maximum compatibility  
- ✅ All scanning and SSH tunneling functionality works unchanged
- ✅ Complete text-based reports and JSON data export

## Security Considerations

⚠️ **WARNING**: This tool is designed for authorized security testing only.

- Only use on networks you own or have explicit permission to test
- Ensure proper authorization before running scans
- Be aware that SSH tunneling may trigger security alerts
- Tool creates temporary files that are cleaned up automatically
- All credentials are used for legitimate security assessment purposes

## Network Map Legend

- **Red Square**: Pivot Device (starting point)
- **Green Diamond**: Network Segment  
- **Teal Circle**: SSH Accessible Device
- **Blue Circle**: Discovered Device (no SSH access)
- **Yellow Triangle**: Multi-Network Device (potential cycle)
- **Red Dashed Line**: Cross-Network Connection (cycle detected)

## Troubleshooting

1. **Permission Denied**: Ensure script is run with sudo
2. **Dependencies Missing**: Run `./setup.sh` to install requirements
3. **SSH Timeout**: Check credentials and network connectivity
4. **Visualization Issues**: Install Python graphics dependencies: `pip3 install networkx matplotlib numpy`
5. **Port Conflicts**: 
   - Tool automatically finds available ports, but if all ports are busy:
   - Check for other proxy tools (Tor, Burp Suite, etc.) using common SOCKS ports
   - Kill existing SSH tunnels: `pkill -f 'ssh.*-D'`
   - Free up ports 8000-8009, 9050-9054, or 1080-1084
6. **Proxychains Issues**:
   - Ensure proxychains4 is installed: `apt install proxychains4` or `brew install proxychains-ng`
   - Check if SOCKS proxy is responding: Tool includes automatic health checks
   - Try manual test: `proxychains4 curl http://www.google.com`
7. **Tunnel Creation Failures**:
   - Check SSH key conflicts: Tool uses password authentication
   - Verify target SSH service is running: `nmap -p 22 target_ip`
   - Check firewall rules allowing outbound SSH connections

## Technical Details

The tool operates in phases:
1. **Local Enumeration**: Discover pivot device network configuration
2. **Network Discovery**: Ping sweep and initial port scanning from pivot
3. **Cycle Detection**: Check for already-scanned networks and devices
4. **Credential Testing**: Attempt SSH access to discovered devices
5. **Path Analysis**: Determine shortest SSH paths to avoid redundant tunnels
6. **Tunnel Creation**: Establish SOCKS proxies through optimal SSH paths
7. **Deep Scanning**: Scan additional networks through tunnels with deduplication
8. **Topology Analysis**: Identify cross-network connections and potential cycles
9. **Visualization**: Generate network topology maps showing cycles and connections

**Cycle Detection Features:**
- **Network Deduplication**: Prevents re-scanning the same network ranges
- **Device Deduplication**: Tracks discovered devices globally to avoid duplicates  
- **Path Optimization**: Uses shortest paths for SSH tunneling
- **Cross-Network Detection**: Identifies devices accessible from multiple networks
- **Infinite Loop Prevention**: Stops cycles in SSH tunnel chains

**SSH Tunnel Port Management:**
- **Dynamic Port Selection**: Automatically finds available ports from a curated list
- **Port Fallback Chain**: Tries common SOCKS ports (8000-8009, 9050-9054, 1080-1084, etc.)
- **Port Conflict Resolution**: Detects and avoids already-used ports
- **Tunnel Health Checking**: Tests SOCKS proxy functionality before use
- **Automatic Retry**: Attempts multiple ports if initial tunnel creation fails
- **Graceful Cleanup**: Properly terminates tunnels and frees ports on exit

SSH tunnels use dynamic port forwarding (SOCKS5) with intelligent port selection. Proxychains configurations are dynamically generated for each tunnel with optimized timeouts and local network bypass rules. The tool maintains a global topology map tracking all device relationships and network overlaps. 
