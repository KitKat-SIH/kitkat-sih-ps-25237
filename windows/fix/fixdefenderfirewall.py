#!/usr/bin/env python3
"""
Windows Defender Firewall Auto-Fix Script
Fixes Windows Defender Firewall configuration for security compliance
"""

import subprocess
import os
import platform
import ctypes
import sys
import time

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    print()
    print("WINDOWS DEFENDER FIREWALL AUTO-FIX")
    print(f"{Colors.BLUE}=" * 50 + f"{Colors.END}")
    print("Automatically configures firewall for security compliance")

def is_admin():
    """Check if running as administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_windows_os():
    """Verify the script is running on Windows"""
    if platform.system() != "Windows":
        print(f"{Colors.RED}[ERROR]{Colors.END} This script can only run on Windows operating systems.")
        sys.exit(1)

def enable_firewall_profiles():
    """Enable Windows Defender Firewall for all profiles"""
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Enabling Windows Defender Firewall for all profiles...")
    
    try:
        # Enable firewall for all profiles
        result = subprocess.run([
            "netsh", "advfirewall", "set", "allprofiles", "state", "on"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Windows Defender Firewall enabled for all profiles")
            
            # Set firewall policy to block inbound, allow outbound
            result2 = subprocess.run([
                "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"
            ], capture_output=True, text=True, timeout=30)
            
            if result2.returncode == 0:
                print(f"{Colors.GREEN}[FIXED]{Colors.END} Firewall policy set to block inbound, allow outbound")
                return True
            else:
                print(f"{Colors.RED}[FAILED]{Colors.END} Failed to set firewall policy")
                return False
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Failed to enable firewall profiles")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error enabling firewall profiles: {e}")
        return False

def create_firewall_rules():
    """Create critical firewall blocking rules"""
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Creating critical firewall blocking rules...")
    
    rules = [
        {
            "name": "Block SMB v1",
            "command": ["netsh", "advfirewall", "firewall", "add", "rule", 
                       "name=Block SMB v1", "dir=in", "action=block", "protocol=TCP", "localport=445"]
        },
        {
            "name": "Block NetBIOS 137",
            "command": ["netsh", "advfirewall", "firewall", "add", "rule", 
                       "name=Block NetBIOS 137", "dir=in", "action=block", "protocol=UDP", "localport=137"]
        },
        {
            "name": "Block NetBIOS 138",
            "command": ["netsh", "advfirewall", "firewall", "add", "rule", 
                       "name=Block NetBIOS 138", "dir=in", "action=block", "protocol=UDP", "localport=138"]
        },
        {
            "name": "Block NetBIOS 139",
            "command": ["netsh", "advfirewall", "firewall", "add", "rule", 
                       "name=Block NetBIOS 139", "dir=in", "action=block", "protocol=TCP", "localport=139"]
        },
        {
            "name": "Block RDP External",
            "command": ["netsh", "advfirewall", "firewall", "add", "rule", 
                       "name=Block RDP External", "dir=in", "action=block", "protocol=TCP", "localport=3389"]
        }
    ]
    
    success_count = 0
    
    for rule in rules:
        try:
            # First, try to delete existing rule in case it exists
            delete_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule['name']}"]
            subprocess.run(delete_cmd, capture_output=True, timeout=30)
            
            # Add the new rule
            result = subprocess.run(rule["command"], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[CREATED]{Colors.END} {rule['name']}")
                success_count += 1
            else:
                print(f"{Colors.RED}[FAILED]{Colors.END} {rule['name']}: {result.stderr}")
                
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.END} {rule['name']}: {e}")
    
    print(f"{Colors.BLUE}[RESULT]{Colors.END} Created {success_count}/{len(rules)} firewall rules")
    return success_count == len(rules)

def enable_firewall_logging():
    """Enable firewall logging for dropped connections"""
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Enabling firewall logging...")
    
    try:
        # Enable logging for dropped connections on all profiles
        result = subprocess.run([
            "netsh", "advfirewall", "set", "allprofiles", "logging", "droppedconnections", "enable"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Firewall logging enabled for dropped connections")
            
            # Set log file size (optional)
            result2 = subprocess.run([
                "netsh", "advfirewall", "set", "allprofiles", "logging", "maxfilesize", "4096"
            ], capture_output=True, text=True, timeout=30)
            
            if result2.returncode == 0:
                print(f"{Colors.GREEN}[FIXED]{Colors.END} Firewall log file size set to 4MB")
            
            return True
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Failed to enable firewall logging")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error enabling firewall logging: {e}")
        return False

def restart_firewall_service():
    """Restart Windows Defender Firewall service"""
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Restarting Windows Defender Firewall service...")
    
    try:
        # Stop the service
        result1 = subprocess.run([
            "net", "stop", "MpsSvc"
        ], capture_output=True, text=True, timeout=30)
        
        time.sleep(2)
        
        # Start the service
        result2 = subprocess.run([
            "net", "start", "MpsSvc"
        ], capture_output=True, text=True, timeout=30)
        
        if result2.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Windows Defender Firewall service restarted")
            return True
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Failed to restart firewall service")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error restarting firewall service: {e}")
        return False

def verify_fixes():
    """Verify that firewall fixes were applied successfully"""
    print(f"{Colors.YELLOW}[VERIFYING]{Colors.END} Checking firewall configuration...")
    
    try:
        # Check if firewall is enabled
        result = subprocess.run([
            "netsh", "advfirewall", "show", "allprofiles", "state"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            if "state" in output and "on" in output:
                print(f"{Colors.GREEN}[VERIFIED]{Colors.END} Firewall is enabled")
                return True
            else:
                print(f"{Colors.RED}[FAILED]{Colors.END} Firewall verification failed")
                return False
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Could not verify firewall status")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error verifying firewall: {e}")
        return False

def main():
    """Main function"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print("Please run this script as Administrator.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges")
    
    print(f"\n{Colors.BLUE}[INFO]{Colors.END} This script will configure Windows Defender Firewall for security compliance:")
    print("  • Enable firewall for all profiles")
    print("  • Set policy to block inbound connections")
    print("  • Create blocking rules for high-risk ports")
    print("  • Enable firewall logging")
    print("  • Restart firewall service")
    
    confirm = input(f"\n{Colors.YELLOW}[CONFIRM]{Colors.END} Apply firewall security fixes? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Firewall fixes cancelled by user")
        sys.exit(0)
    
    print()
    
    try:
        # Apply firewall fixes
        profiles_success = enable_firewall_profiles()
        time.sleep(2)
        
        rules_success = create_firewall_rules()
        time.sleep(2)
        
        logging_success = enable_firewall_logging()
        time.sleep(2)
        
        service_success = restart_firewall_service()
        time.sleep(2)
        
        verification_success = verify_fixes()
        
        # Summary
        print(f"\n{Colors.BOLD}FIREWALL FIX SUMMARY{Colors.END}")
        print("=" * 50)
        
        fixes_applied = 0
        total_fixes = 5
        
        if profiles_success:
            fixes_applied += 1
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Firewall profiles enabled")
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Firewall profiles")
        
        if rules_success:
            fixes_applied += 1
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Critical firewall rules created")
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Critical firewall rules")
        
        if logging_success:
            fixes_applied += 1
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Firewall logging enabled")
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Firewall logging")
        
        if service_success:
            fixes_applied += 1
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Firewall service restarted")
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Firewall service restart")
        
        if verification_success:
            fixes_applied += 1
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Configuration verified")
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Configuration verification")
        
        print(f"\n{Colors.BLUE}[RESULT]{Colors.END} {fixes_applied}/{total_fixes} firewall fixes applied successfully")
        
        if fixes_applied == total_fixes:
            print(f"\n{Colors.GREEN}[COMPLETE]{Colors.END} Windows Defender Firewall is now properly configured!")
            print("Your system has enhanced network security protection.")
        elif fixes_applied >= 3:
            print(f"\n{Colors.YELLOW}[PARTIAL]{Colors.END} Most firewall fixes applied successfully.")
            print("Some manual configuration may be required.")
        else:
            print(f"\n{Colors.RED}[FAILED]{Colors.END} Firewall configuration failed.")
            print("Manual firewall configuration required.")
        
        print(f"\n{Colors.BLUE}[NEXT STEPS]{Colors.END}")
        print("1. Test network connectivity")
        print("2. Configure firewall exceptions for required applications")
        print("3. Monitor firewall logs for blocked connections")
        print("4. Regular firewall rule maintenance")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.END} Firewall fix interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[ERROR]{Colors.END} Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()