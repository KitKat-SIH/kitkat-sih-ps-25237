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
    print("CHECKING WINDOWS SECURITY OPTIONS")
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
    temp_path = os.path.join(cwd, "security_options_export.inf")
    
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

def check_accounts_policies(policy_data):
    """Check Accounts security options"""
    print(f"\n{Colors.BOLD}ACCOUNTS SECURITY OPTIONS{Colors.END}")
    print("-" * 80)
    
    accounts_checks = {
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\NoConnectedUser": {
            "description": "Block Microsoft accounts",
            "requirement": "Users can't add or log on with Microsoft accounts",
            "expected_value": "3",
            "check_type": "exact"
        },
        "EnableGuestAccount": {
            "description": "Guest account status",
            "requirement": "Disabled",
            "expected_value": "0",
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse": {
            "description": "Limit local account use of blank passwords to console logon only",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "NewAdministratorName": {
            "description": "Rename administrator account",
            "requirement": "Configure (not 'Administrator')",
            "expected_value": "not_administrator",
            "check_type": "not_default"
        },
        "NewGuestName": {
            "description": "Rename guest account",
            "requirement": "Configure (not 'Guest')",
            "expected_value": "not_guest",
            "check_type": "not_default"
        }
    }
    
    return check_security_options_section(policy_data, accounts_checks, "Accounts")

def check_interactive_logon_policies(policy_data):
    """Check Interactive logon security options"""
    print(f"\n{Colors.BOLD}INTERACTIVE LOGON SECURITY OPTIONS{Colors.END}")
    print("-" * 80)
    
    interactive_checks = {
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD": {
            "description": "Do not require CTRL+ALT+DEL",
            "requirement": "Disabled",
            "expected_value": "0",
            "check_type": "exact"
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName": {
            "description": "Don't display last signed in",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\MaxDevicePasswordFailedAttempts": {
            "description": "Machine account lockout threshold",
            "requirement": "10 or fewer invalid logon attempts, but not 0",
            "expected_value": "10",
            "check_type": "max_not_zero",
            "max_value": 10
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs": {
            "description": "Machine inactivity limit",
            "requirement": "900 or fewer second(s), but not 0",
            "expected_value": "900",
            "check_type": "max_not_zero",
            "max_value": 900
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText": {
            "description": "Message text for users attempting to log on",
            "requirement": "Configure (should not be empty)",
            "expected_value": "configured",
            "check_type": "not_empty"
        },
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption": {
            "description": "Message title for users attempting to log on",
            "requirement": "Configure (should not be empty)",
            "expected_value": "configured",
            "check_type": "not_empty"
        },
        "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\PasswordExpiryWarning": {
            "description": "Prompt user to change password before expiration",
            "requirement": "between 5 and 14 days",
            "expected_value": "14",
            "check_type": "range",
            "min_value": 5,
            "max_value": 14
        }
    }
    
    return check_security_options_section(policy_data, interactive_checks, "Interactive Logon")

def check_network_server_policies(policy_data):
    """Check Microsoft network server security options"""
    print(f"\n{Colors.BOLD}MICROSOFT NETWORK SERVER SECURITY OPTIONS{Colors.END}")
    print("-" * 80)
    
    network_checks = {
        "MACHINE\\System\\CurrentControlSet\\Services\\lanmanserver\\parameters\\autodisconnect": {
            "description": "Amount of idle time required before suspending session",
            "requirement": "15 or fewer minute(s)",
            "expected_value": "15",
            "check_type": "max",
            "max_value": 15
        },
        "MACHINE\\System\\CurrentControlSet\\Services\\lanmanserver\\parameters\\enableforcedlogoff": {
            "description": "Disconnect clients when logon hours expire",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\TurnOffAnonymousBlock": {
            "description": "Allow anonymous SID/Name translation",
            "requirement": "Disabled",
            "expected_value": "0",
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM": {
            "description": "Do not allow anonymous enumeration of SAM accounts",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous": {
            "description": "Do not allow anonymous enumeration of SAM accounts and shares",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\DisableDomainCreds": {
            "description": "Do not allow storage of passwords and credentials for network authentication",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous": {
            "description": "Let Everyone permissions apply to anonymous users",
            "requirement": "Disabled",
            "expected_value": "0",
            "check_type": "exact"
        }
    }
    
    return check_security_options_section(policy_data, network_checks, "Network Server")

def check_network_security_policies(policy_data):
    """Check Network security options"""
    print(f"\n{Colors.BOLD}NETWORK SECURITY OPTIONS{Colors.END}")
    print("-" * 80)
    
    security_checks = {
        "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\SupportedEncryptionTypes": {
            "description": "Configure encryption types allowed for Kerberos",
            "requirement": "AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types",
            "expected_value": "2147483644",  # This represents the required encryption types
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash": {
            "description": "Do not store LAN Manager hash value on next password change",
            "requirement": "Enabled",
            "expected_value": "1",
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity": {
            "description": "LDAP client signing requirements",
            "requirement": "Negotiate signing or higher",
            "expected_value": "1",
            "check_type": "minimum",
            "min_value": 1
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec": {
            "description": "Minimum session security for NTLM SSP based clients",
            "requirement": "Require NTLMv2 session security, Require 128-bit encryption",
            "expected_value": "537395200",
            "check_type": "exact"
        },
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec": {
            "description": "Minimum session security for NTLM SSP based servers",
            "requirement": "Require NTLMv2 session security, Require 128-bit encryption",
            "expected_value": "537395200",
            "check_type": "exact"
        }
    }
    
    return check_security_options_section(policy_data, security_checks, "Network Security")

def check_security_options_section(policy_data, checks, section_name):
    """Generic function to check security options"""
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
            
        elif config["check_type"] == "max":
            try:
                current_int = int(current_value)
                max_val = config["max_value"]
                is_compliant = current_int <= max_val
                status_detail = f"Current: {current_int}, Required: {max_val} or fewer"
            except ValueError:
                status_detail = f"Current: {current_value} (invalid), Required: {config['max_value']} or fewer"
                
        elif config["check_type"] == "max_not_zero":
            try:
                current_int = int(current_value)
                max_val = config["max_value"]
                is_compliant = 0 < current_int <= max_val
                status_detail = f"Current: {current_int}, Required: {max_val} or fewer (not 0)"
            except ValueError:
                status_detail = f"Current: {current_value} (invalid), Required: {config['max_value']} or fewer (not 0)"
                
        elif config["check_type"] == "minimum":
            try:
                current_int = int(current_value)
                min_val = config["min_value"]
                is_compliant = current_int >= min_val
                status_detail = f"Current: {current_int}, Required: {min_val} or higher"
            except ValueError:
                status_detail = f"Current: {current_value} (invalid), Required: {config['min_value']} or higher"
                
        elif config["check_type"] == "range":
            try:
                current_int = int(current_value)
                min_val = config["min_value"]
                max_val = config["max_value"]
                is_compliant = min_val <= current_int <= max_val
                status_detail = f"Current: {current_int}, Required: {min_val}-{max_val}"
            except ValueError:
                status_detail = f"Current: {current_value} (invalid), Required: {config['min_value']}-{config['max_value']}"
                
        elif config["check_type"] == "not_default":
            if policy_key == "NewAdministratorName":
                is_compliant = current_value.lower() not in ["administrator", "admin"]
                status_detail = f"Current: {current_value}, Required: Not 'Administrator'"
            elif policy_key == "NewGuestName":
                is_compliant = current_value.lower() not in ["guest"]
                status_detail = f"Current: {current_value}, Required: Not 'Guest'"
                
        elif config["check_type"] == "not_empty":
            is_compliant = len(current_value.strip()) > 0
            status_detail = f"Current: {'Configured' if is_compliant else 'Empty'}, Required: Configured"
        
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
    """Main function to orchestrate the security options checking"""
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
        
        # Check all security options categories
        accounts_compliant = check_accounts_policies(policy_data)
        interactive_compliant = check_interactive_logon_policies(policy_data)
        network_server_compliant = check_network_server_policies(policy_data)
        network_security_compliant = check_network_security_policies(policy_data)
        
        # Overall summary
        print(f"\n{Colors.BOLD}SECURITY OPTIONS COMPLIANCE SUMMARY{Colors.END}")
        print(f"{Colors.BLUE}={'=' * 80}{Colors.END}")
        
        accounts_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if accounts_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        interactive_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if interactive_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        server_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if network_server_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        security_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if network_security_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        
        print(f"Accounts Security Options:           {accounts_status}")
        print(f"Interactive Logon Security Options:  {interactive_status}")
        print(f"Network Server Security Options:     {server_status}")
        print(f"Network Security Options:            {security_status}")
        
        overall_compliant = all([accounts_compliant, interactive_compliant, network_server_compliant, network_security_compliant])
        overall_status = f"{Colors.GREEN}FULLY COMPLIANT{Colors.END}" if overall_compliant else f"{Colors.RED}REQUIRES ATTENTION{Colors.END}"
        
        print(f"\nOverall Security Options Status:     {overall_status}")
    
        
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error processing policy data: {str(e)}")
    
    finally:
        cleanup_temp_files(temp_file)

if __name__ == "__main__":
    main()