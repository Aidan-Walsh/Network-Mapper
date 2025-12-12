#!/usr/bin/env python3
"""
Check Python version and test subprocess compatibility
"""

import sys
import subprocess

def check_python_version():
    """Check Python version and compatibility"""
    print("=== Python Version Check ===")
    print(f"Python version: {sys.version}")
    print(f"Version info: {sys.version_info}")
    
    if sys.version_info >= (3, 6):
        print("✅ Python 3.6+ detected - compatible!")
        return True
    else:
        print("❌ Python version too old - need Python 3.6+")
        return False

def test_subprocess_compatibility():
    """Test subprocess.run with Python 3.6 compatible syntax"""
    print("\n=== Testing subprocess compatibility ===")
    
    try:
        # Test the Python 3.6 compatible way
        result = subprocess.run(
            ["echo", "test"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True
        )
        print("✅ subprocess.run with stdout/stderr works")
        print(f"   Output: {result.stdout.strip()}")
        
    except Exception as e:
        print(f"❌ subprocess.run failed: {e}")
        return False
    
    try:
        # Test with shell=True
        result = subprocess.run(
            "echo 'shell test'", 
            shell=True,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True
        )
        print("✅ subprocess.run with shell=True works")
        print(f"   Output: {result.stdout.strip()}")
        
    except Exception as e:
        print(f"❌ subprocess.run with shell failed: {e}")
        return False
    
    # Test if capture_output exists (Python 3.7+)
    try:
        result = subprocess.run(
            ["echo", "capture_output_test"],
            capture_output=True,
            text=True
        )
        print("ℹ️  capture_output parameter available (Python 3.7+)")
    except TypeError:
        print("ℹ️  capture_output not available - using Python 3.6 compatible version")
    
    return True

def test_basic_network_commands():
    """Test basic network commands that the mapper needs"""
    print("\n=== Testing Required Network Commands ===")
    
    commands = [
        ("ip a", "IP address command"),
        ("arp -a", "ARP table command"), 
        ("ss -ntlp", "Socket statistics command"),
        ("nmap --version", "Nmap version check"),
        ("hostname", "Hostname command")
    ]
    
    for cmd, desc in commands:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10
            )
            if result.returncode == 0:
                print(f"✅ {desc}: Available")
            else:
                print(f"⚠️  {desc}: Command failed (return code {result.returncode})")
        except FileNotFoundError:
            print(f"❌ {desc}: Command not found")
        except Exception as e:
            print(f"❌ {desc}: Error - {e}")

def main():
    print("Network Mapper Python Compatibility Check")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        print("\n❌ CRITICAL: Python version incompatible")
        print("Please upgrade to Python 3.6 or higher")
        sys.exit(1)
    
    # Test subprocess
    if not test_subprocess_compatibility():
        print("\n❌ CRITICAL: subprocess compatibility issues")
        sys.exit(1)
    
    # Test network commands
    test_basic_network_commands()
    
    print("\n" + "=" * 50)
    print("✅ Environment check complete!")
    print("Your system should be compatible with the network mapper.")
    print("\nNext steps:")
    print("1. Run: ./setup.sh")
    print("2. Run: sudo python3 mapper.py")

if __name__ == "__main__":
    main()