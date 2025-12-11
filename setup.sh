#!/bin/bash

echo "Network Mapper Setup Script"
echo "==========================="

# Check if running as root/sudo
if [[ $EUID -eq 0 ]]; then
   echo "Do not run this script as root. Some operations need to be run as regular user."
   exit 1
fi

echo "Installing Python dependencies..."
pip3 install -r requirements.txt

echo "Checking for GUI environment..."
if [[ -z "$DISPLAY" && -z "$WAYLAND_DISPLAY" && -z "$XDG_SESSION_TYPE" ]]; then
    echo "⚠️  Headless environment detected (no GUI)"
    echo "   → ASCII network maps will be generated instead of graphical ones"
    echo "   → All functionality remains available"
else
    echo "✅ GUI environment detected - full graphical maps available"
fi

echo "Installing system dependencies..."
# Check OS and install accordingly
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Detected Linux. Please ensure the following packages are installed:"
    echo "- nmap"
    echo "- sshpass" 
    echo "- proxychains4"
    echo ""
    echo "On Ubuntu/Debian: sudo apt-get install nmap sshpass proxychains4"
    echo "On RHEL/CentOS: sudo yum install nmap sshpass proxychains-ng"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS. Installing dependencies via Homebrew..."
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Please install it from https://brew.sh/"
        exit 1
    fi
    brew install nmap sshpass proxychains-ng
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "Making scripts executable..."
chmod +x scanner.sh
chmod +x setup.sh

echo ""
echo "Setup complete!"
echo ""
echo "Usage:"
echo "1. Edit credentials.txt with target credentials (format: username:password)"
echo "2. Run: python3 mapper.py"
echo ""
echo "Note: Ensure you have sudo access and proper authorization before scanning networks."