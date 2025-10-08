#!/usr/bin/env python3
import subprocess
import os
import re
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
    print("CHECKING WINDOWS SYSTEM SETTINGS")
    print(f"{Colors.BLUE}=" * 80 + f"{Colors.END}")

def is_admin():
    """Check if running as administrator using ctypes"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_windows_os():
    """Verify the script is running on Windows"""
    if platform.system() != "Windows":
        print(f"{Colors.RED}[ERROR]{Colors.END} This script can only run on Windows operating systems.")
        print(f"Current OS: {platform.system()}")
        sys.exit(1)

def export_security_policy():
    """Export Windows security policy to a temporary file"""
    cwd = os.getcwd()
    temp_path = os.path.join(cwd, "system_settings_export.inf")
    
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Exporting Windows security policy...")
    time.sleep(1)
    
    result = subprocess.run(
        ["secedit", "/export", "/cfg", temp_path, "/quiet"],
        capture_output=True, 
        text=True
    )
    
    if result.returncode != 0:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to export security policy")
        print(f"Return code: {result.returncode}")
        if result.stderr:
            print(f"Error details: {result.stderr}")
        return None
    
    if not os.path.exists(temp_path):
        print(f"{Colors.RED}[ERROR]{Colors.END} Policy export file not created: {temp_path}")
        return None
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Security policy exported successfully")
    return temp_path

def parse_policy_data(file_path):
    """Read and parse the exported policy file"""
    try:
        with open(file_path, "r", encoding="utf-16") as f:
            data = f.read()
    except UnicodeError:
        with open(file_path, "r") as f:
            data = f.read()
    return data

def get_service_status(service_name):
    """Get the status of a Windows service"""
    try:
        # Query service configuration
        result = subprocess.run(
            ["sc", "qc", service_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            output = result.stdout
            # Extract START_TYPE from output
            start_type_match = re.search(r'START_TYPE\s*:\s*\d+\s+(\w+)', output)
            if start_type_match:
                start_type = start_type_match.group(1).upper()
                return start_type
            else:
                return "UNKNOWN"
        else:
            # Service might not exist
            return "NOT_INSTALLED"
            
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return "NOT_INSTALLED"

def check_uac_policies(policy_data):
    """Check User Account Control security options"""
    print(f"\n{Colors.BOLD}USER ACCOUNT CONTROL (UAC) SETTINGS{Colors.END}")
    print("-" * 80)
    
    uac_checks = {
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken": {
            "description": "Admin Approval Mode for the Built-in Administrator account",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin": {
            "description": "Behaviour of the elevation prompt for administrators in Admin Approval Mode",
            "requirement": "Prompt for consent on the secure desktop or higher",
            "expected_value": "2",
            "check_type": "minimum",
            "min_value": 2
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser": {
            "description": "Behaviour of the elevation prompt for standard users",
            "requirement": "Automatically deny elevation requests",
            "expected_value": "0",
            "check_type": "exact"
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableInstallerDetection": {
            "description": "Detect application installations and prompt for elevation",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA": {
            "description": "Run all administrators in Admin Approval Mode",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop": {
            "description": "Switch to the secure desktop when prompting for elevation",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        }
    }
    
    return check_security_options_section(policy_data, uac_checks, "User Account Control")

def check_system_services():
    """Check System Services configuration"""
    print(f"\n{Colors.BOLD}SYSTEM SERVICES CONFIGURATION{Colors.END}")
    print("-" * 80)
    
    services_checks = {
        "BTAGService": {
            "description": "Bluetooth Audio Gateway Service",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "bthserv": {
            "description": "Bluetooth Support Service",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "Browser": {
            "description": "Computer Browser",
            "requirement": "Disabled or Not Installed",
            "expected_status": ["DISABLED", "NOT_INSTALLED"]
        },
        "lfsvc": {
            "description": "Geolocation Service",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "SharedAccess": {
            "description": "Internet Connection Sharing (ICS)",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "SessionEnv": {
            "description": "Remote Desktop Configuration",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "TermService": {
            "description": "Remote Desktop Services",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "UmRdpService": {
            "description": "Remote Desktop Services UserMode Port Redirector",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "RpcLocator": {
            "description": "Remote Procedure Call (RPC) Locator",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "RemoteRegistry": {
            "description": "Remote Registry",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "RemoteAccess": {
            "description": "Routing and Remote Access",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "simptcp": {
            "description": "Simple TCP/IP Services",
            "requirement": "Disabled or Not Installed",
            "expected_status": ["DISABLED", "NOT_INSTALLED"]
        },
        "SNMP": {
            "description": "SNMP Service",
            "requirement": "Disabled or Not Installed",
            "expected_status": ["DISABLED", "NOT_INSTALLED"]
        },
        "upnphost": {
            "description": "UPnP Device Host",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "WMSvc": {
            "description": "Web Management Service",
            "requirement": "Disabled or Not Installed",
            "expected_status": ["DISABLED", "NOT_INSTALLED"]
        },
        "WerSvc": {
            "description": "Windows Error Reporting Service",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "Wecsvc": {
            "description": "Windows Event Collector",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "WMPNetworkSvc": {
            "description": "Windows Media Player Network Sharing Service",
            "requirement": "Disabled or Not Installed",
            "expected_status": ["DISABLED", "NOT_INSTALLED"]
        },
        "icssvc": {
            "description": "Windows Mobile Hotspot Service",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "PushToInstall": {
            "description": "Windows PushToInstall Service",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "WinRM": {
            "description": "Windows Remote Management (WS Management)",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "W3SVC": {
            "description": "World Wide Web Publishing Service",
            "requirement": "Disabled or Not Installed",
            "expected_status": ["DISABLED", "NOT_INSTALLED"]
        },
        "XboxGipSvc": {
            "description": "Xbox Accessory Management Service",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "XblAuthManager": {
            "description": "Xbox Live Auth Manager",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "XblGameSave": {
            "description": "Xbox Live Game Save",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        },
        "XboxNetApiSvc": {
            "description": "Xbox Live Networking Service",
            "requirement": "Disabled",
            "expected_status": "DISABLED"
        }
    }
    
    compliant_count = 0
    total_checks = len(services_checks)
    
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Checking system services configuration...")
    time.sleep(1)
    
    for service_name, config in services_checks.items():
        current_status = get_service_status(service_name)
        expected_status = config["expected_status"]
        
        # Handle both single expected status and list of acceptable statuses
        if isinstance(expected_status, list):
            is_compliant = current_status in expected_status
        else:
            is_compliant = current_status == expected_status
        
        # Display result
        status_icon = f"{Colors.GREEN}[COMPLIANT]{Colors.END}" if is_compliant else f"{Colors.RED}[NON-COMPLIANT]{Colors.END}"
        
        # Format expected status for display
        if isinstance(expected_status, list):
            expected_display = " or ".join(expected_status)
        else:
            expected_display = expected_status
        
        print(f"{status_icon} {config['description']} ({service_name})")
        print(f"               Required: {config['requirement']}")
        print(f"               Status: Current: {current_status}, Required: {expected_display}")
        print()
        
        if is_compliant:
            compliant_count += 1
    
    # Services summary
    compliance_percentage = (compliant_count / total_checks) * 100 if total_checks > 0 else 0
    
    if compliant_count == total_checks:
        summary_color = Colors.GREEN
        summary_status = "FULLY COMPLIANT"
    elif compliant_count >= total_checks * 0.8:
        summary_color = Colors.YELLOW
        summary_status = "MOSTLY COMPLIANT"
    else:
        summary_color = Colors.RED
        summary_status = "NON-COMPLIANT"
    
    print(f"{summary_color}[{summary_status}]{Colors.END} System Services Compliance: {compliant_count}/{total_checks} ({compliance_percentage:.1f}%)\n")
    
    return compliant_count == total_checks

def check_security_options_section(policy_data, checks, section_name):
    """Generic function to check security options from policy export"""
    compliant_count = 0
    total_checks = len(checks)
    
    # Look for Registry Values section
    registry_section = re.search(r'\[Registry Values\](.*?)(?=\[|$)', policy_data, re.DOTALL | re.IGNORECASE)
    if registry_section:
        registry_data = registry_section.group(1)
    else:
        registry_data = policy_data
    
    for policy_key, config in checks.items():
        # Search for the policy in the exported data
        patterns = [
            rf"^{re.escape(policy_key)}\s*=\s*(.*?)$",
            rf"^\s*{re.escape(policy_key)}\s*=\s*(.*?)$",
            rf"{re.escape(policy_key)}\s*=\s*([^,\r\n]*)"
        ]
        
        match = None
        for pattern in patterns:
            match = re.search(pattern, registry_data, re.MULTILINE | re.IGNORECASE)
            if match:
                break
        
        if not match:
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {config['description']}")
            print(f"               Required: {config['requirement']}")
            print(f"               Status: Not found in policy export - check manually in gpedit.msc")
            print(f"               Path: Local Computer Policy > Computer Configuration > Windows Settings")
            print(f"                     > Security Settings > Local Policies > Security Options\n")
            continue
        
        # Extract the current value
        current_value_raw = match.group(1).strip()
        # Remove registry type information if present (e.g., "4,1" -> "1")
        if ',' in current_value_raw:
            current_value = current_value_raw.split(',')[-1].strip()
        else:
            current_value = current_value_raw.strip('"')
        
        # Check compliance based on check type
        is_compliant = False
        status_detail = ""
        
        if config["check_type"] == "exact":
            is_compliant = current_value == config["expected_value"]
            status_detail = f"Current: {current_value}, Required: {config['expected_value']}"
            
        elif config["check_type"] == "minimum":
            try:
                current_int = int(current_value)
                min_val = config["min_value"]
                is_compliant = current_int >= min_val
                
                # Special handling for UAC elevation prompt behavior
                if policy_key.endswith("ConsentPromptBehaviorAdmin"):
                    behavior_map = {
                        "0": "Elevate without prompting",
                        "1": "Prompt for credentials on the secure desktop",
                        "2": "Prompt for consent on the secure desktop",
                        "3": "Prompt for credentials",
                        "4": "Prompt for consent",
                        "5": "Prompt for consent for non-Windows binaries"
                    }
                    current_desc = behavior_map.get(current_value, f"Unknown ({current_value})")
                    status_detail = f"Current: {current_desc}, Required: Prompt for consent on the secure desktop or higher"
                else:
                    status_detail = f"Current: {current_int}, Required: {min_val} or higher"
            except ValueError:
                status_detail = f"Current: {current_value} (invalid), Required: {config['min_value']} or higher"
        
        # Display result
        status_icon = f"{Colors.GREEN}[COMPLIANT]{Colors.END}" if is_compliant else f"{Colors.RED}[NON-COMPLIANT]{Colors.END}"
        
        print(f"{status_icon} {config['description']}")
        print(f"               Required: {config['requirement']}")
        print(f"               Status: {status_detail}")
        print()
        
        if is_compliant:
            compliant_count += 1
    
    # Section summary
    compliance_percentage = (compliant_count / total_checks) * 100 if total_checks > 0 else 0
    
    if compliant_count == total_checks:
        summary_color = Colors.GREEN
        summary_status = "FULLY COMPLIANT"
    elif compliant_count >= total_checks * 0.8:
        summary_color = Colors.YELLOW
        summary_status = "MOSTLY COMPLIANT"
    else:
        summary_color = Colors.RED
        summary_status = "NON-COMPLIANT"
    
    print(f"{summary_color}[{summary_status}]{Colors.END} {section_name} Compliance: {compliant_count}/{total_checks} ({compliance_percentage:.1f}%)\n")
    
    return compliant_count == total_checks

def cleanup_temp_files(file_path):
    """Clean up temporary files"""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Cleaning temporary files")
            time.sleep(1)
    except Exception as e:
        print(f"\n{Colors.YELLOW}[WARNING]{Colors.END} Could not remove temporary file: {e}")

def main():
    """Main function to orchestrate the system settings checking"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print(f"Please run this script as Administrator")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    temp_file = export_security_policy()
    if not temp_file:
        print(f"{Colors.RED}[FATAL]{Colors.END} Cannot proceed without security policy export")
        sys.exit(1)
    
    try:
        policy_data = parse_policy_data(temp_file)
        
        # Check User Account Control settings
        uac_compliant = check_uac_policies(policy_data)
        
        # Check System Services
        services_compliant = check_system_services()
        
        # Overall summary
        print(f"\n{Colors.BOLD}SYSTEM SETTINGS COMPLIANCE SUMMARY{Colors.END}")
        print(f"{Colors.BLUE}={'=' * 80}{Colors.END}")
        
        uac_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if uac_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        services_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if services_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        
        print(f"User Account Control (UAC):          {uac_status}")
        print(f"System Services:                     {services_status}")
        
        overall_compliant = all([uac_compliant, services_compliant])
        overall_status = f"{Colors.GREEN}FULLY COMPLIANT{Colors.END}" if overall_compliant else f"{Colors.RED}REQUIRES ATTENTION{Colors.END}"
        
        print(f"\nOverall System Settings Status:      {overall_status}")
        
        if not overall_compliant:
            print(f"\n{Colors.YELLOW}[REMEDIATION]{Colors.END} To fix non-compliant settings:")
            print("For UAC Settings:")
            print("1. Open Local Group Policy Editor (gpedit.msc)")
            print("2. Navigate to: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options")
            print("3. Configure the UAC policies as indicated above")
            print()
            print("For System Services:")
            print("1. Open Services Management Console (services.msc)")
            print("2. Locate each non-compliant service")
            print("3. Right-click > Properties > Set Startup type to 'Disabled'")
            print("4. Stop the service if it's currently running")
            print()
            print("5. Run 'gpupdate /force' to apply Group Policy changes immediately")
        
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error processing system settings: {str(e)}")
    
    finally:
        cleanup_temp_files(temp_file)

if __name__ == "__main__":
    main()