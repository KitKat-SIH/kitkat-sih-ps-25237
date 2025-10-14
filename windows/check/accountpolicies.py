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
    print("CHECKING WINDOWS ACCOUNT POLICIES")
    print(f"{Colors.BLUE}=" * 65 + f"{Colors.END}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_windows_os():
    if platform.system() != "Windows":
        print(f"{Colors.RED}[ERROR]{Colors.END} This script can only run on Windows operating systems.")
        print(f"Current OS: {platform.system()}")
        sys.exit(1)

def export_security_policy():
    cwd = os.getcwd()
    temp_path = os.path.join(cwd, "security_policy_export.inf")
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
    try:
        with open(file_path, "r", encoding="utf-16") as f:
            data = f.read()
    except UnicodeError:#without utf16
        with open(file_path, "r") as f:
            data = f.read()
    return data

def check_password_policies(policy_data):
    policy_checks = {
        "PasswordHistorySize": {
            "description": "Enforce password history",
            "requirement": "24 or more password(s)",
            "min_value": 24,
            "check_type": "minimum"
        },
        "MaximumPasswordAge": {
            "description": "Maximum password age",
            "requirement": "90 days, but not 0",
            "expected_value": 90,
            "check_type": "exact_not_zero"
        },
        "MinimumPasswordAge": {
            "description": "Minimum password age",
            "requirement": "1 day",
            "expected_value": 1,
            "check_type": "exact"
        },
        "MinimumPasswordLength": {
            "description": "Minimum password length",
            "requirement": "12 or more character(s)",
            "min_value": 12,
            "check_type": "minimum"
        },
        "PasswordComplexity": {
            "description": "Password must meet complexity requirements",
            "requirement": "Enabled",
            "expected_value": 1,
            "check_type": "exact"
        },
        "ClearTextPassword": {
            "description": "Store passwords using reversible encryption",
            "requirement": "Disabled",
            "expected_value": 0,
            "check_type": "exact"
        }
    }
    
    print(f"\n{Colors.BOLD}PASSWORD POLICY COMPLIANCE REPORT{Colors.END}")
    print("-" * 80)
    
    compliant_count = 0
    total_checks = len(policy_checks)
    
    for policy_key, config in policy_checks.items():
        pattern = rf"^{policy_key}\s*=\s*(\S+)"
        match = re.search(pattern, policy_data, re.MULTILINE | re.IGNORECASE)
        
        if not match:
            print(f"{Colors.RED}[NOT FOUND]{Colors.END} {config['description']}")
            print(f"               Required: {config['requirement']}")
            print(f"               Status: Policy setting not found in export\n")
            continue
        
        try:
            current_value = int(match.group(1))
        except ValueError:
            current_value = match.group(1)
    
        is_compliant = False
        status_detail = ""
        
        if config["check_type"] == "minimum":
            is_compliant = current_value >= config["min_value"]
            status_detail = f"Current: {current_value}, Required: {config['min_value']} or more"
            
        elif config["check_type"] == "exact":
            is_compliant = current_value == config["expected_value"]
            expected_text = "Enabled" if config["expected_value"] == 1 else "Disabled"
            current_text = "Enabled" if current_value == 1 else "Disabled"
            status_detail = f"Current: {current_text}, Required: {expected_text}"
            
        elif config["check_type"] == "exact_not_zero":
            is_compliant = current_value == config["expected_value"] and current_value != 0
            status_detail = f"Current: {current_value} days, Required: {config['expected_value']} days (not 0)"
        
        #results
        status_icon = f"{Colors.GREEN}[COMPLIANT]{Colors.END}" if is_compliant else f"{Colors.RED}[NON-COMPLIANT]{Colors.END}"
        
        print(f"{status_icon} {config['description']}")
        print(f"               Required: {config['requirement']}")
        print(f"               Status: {status_detail}\n")
        
        if is_compliant:
            compliant_count += 1
    
    compliance_percentage = (compliant_count / total_checks) * 100
    
    if compliant_count == total_checks:
        summary_color = Colors.GREEN
        summary_status = "FULLY COMPLIANT"
    elif compliant_count >= total_checks * 0.8:
        summary_color = Colors.YELLOW
        summary_status = "MOSTLY COMPLIANT"
    else:
        summary_color = Colors.RED
        summary_status = "NON-COMPLIANT"
    
    print(f"{summary_color}[{summary_status}]{Colors.END} Password Policy Compliance")
    print(f"Compliant policies: {compliant_count}/{total_checks} ({compliance_percentage:.1f}%)")
    
    return compliant_count == total_checks

def check_account_lockout_policies(policy_data):
    """Check all account lockout policy requirements"""
    
    #checks
    lockout_checks = {
        "LockoutDuration": {
            "description": "Account lockout duration",
            "requirement": "15 or more minute(s)",
            "min_value": 15,
            "check_type": "minimum",
            "unit": "minutes"
        },
        "LockoutBadCount": {
            "description": "Account lockout threshold", 
            "requirement": "5 or fewer invalid logon attempt(s), but not 0",
            "max_value": 5,
            "check_type": "maximum_not_zero",
            "unit": "attempts"
        }
    }
    
    print(f"\n{Colors.BOLD}ACCOUNT LOCKOUT POLICY COMPLIANCE REPORT{Colors.END}")
    
    compliant_count = 0
    total_checks = len(lockout_checks)
    
    for policy_key, config in lockout_checks.items():
        #searching
        pattern = rf"^{policy_key}\s*=\s*(\S+)"
        match = re.search(pattern, policy_data, re.MULTILINE | re.IGNORECASE)
        
        if not match:
            print(f"{Colors.RED}[NOT FOUND]{Colors.END} {config['description']}")
            print(f"               Required: {config['requirement']}")
            print(f"               Status: Policy setting not found in export\n")
            continue
        try:
            current_value = int(match.group(1))
        except ValueError:
            current_value = match.group(1)
        is_compliant = False
        status_detail = ""
        
        if config["check_type"] == "minimum":
            is_compliant = current_value >= config["min_value"]
            status_detail = f"Current: {current_value} {config['unit']}, Required: {config['min_value']} or more {config['unit']}"
            
        elif config["check_type"] == "maximum_not_zero":
            is_compliant = (current_value <= config["max_value"]) and (current_value != 0)
            status_detail = f"Current: {current_value} {config['unit']}, Required: {config['max_value']} or fewer {config['unit']} (not 0)"
        
        status_icon = f"{Colors.GREEN}[COMPLIANT]{Colors.END}" if is_compliant else f"{Colors.RED}[NON-COMPLIANT]{Colors.END}"
        
        print(f"{status_icon} {config['description']}")
        print(f"               Required: {config['requirement']}")
        print(f"               Status: {status_detail}\n")
        
        if is_compliant:
            compliant_count += 1

    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Allow Administrator account lockout")
    print(f"               Required: Enabled")
    print(f"               Status: Manual verification required")
    print(f"               Note: Check registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\DisableLoopbackCheck")
    print(f"                     or use Group Policy: Computer Configuration > Windows Settings > ")
    print(f"                     Security Settings > Local Policies > Security Options\n")
    
    compliance_percentage = (compliant_count / total_checks) * 100
    
    if compliant_count == total_checks:
        summary_color = Colors.GREEN
        summary_status = "FULLY COMPLIANT"
    elif compliant_count >= total_checks * 0.8:
        summary_color = Colors.YELLOW
        summary_status = "MOSTLY COMPLIANT"
    else:
        summary_color = Colors.RED
        summary_status = "NON-COMPLIANT"
    
    print(f"{summary_color}[{summary_status}]{Colors.END} Account Lockout Policy Compliance")
    print(f"Compliant policies: {compliant_count}/{total_checks} ({compliance_percentage:.1f}%)")
    print(f"{Colors.YELLOW}Note:{Colors.END} Administrator account lockout requires manual verification")
    
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
    """Main function to orchestrate the policy checking"""
    print_banner()
    
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges")
    
    temp_file = export_security_policy()
    if not temp_file:
        print(f"{Colors.RED}[FATAL]{Colors.END} Cannot proceed without security policy export")
        sys.exit(1)
    
    try:

        policy_data = parse_policy_data(temp_file)
        
        password_compliant = check_password_policies(policy_data)
        
        lockout_compliant = check_account_lockout_policies(policy_data)
        

        print(f"\n{Colors.BOLD}Account Policies Summary{Colors.END}")
        print(f"{Colors.BLUE}={Colors.END}" * 80)
        
        password_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if password_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        lockout_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if lockout_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        
        print(f"Password Policies:        {password_status}")
        print(f"Account Lockout Policies: {lockout_status}")
        
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error processing policy data: {str(e)}")
    
    finally:
        cleanup_temp_files(temp_file)

if __name__ == "__main__":
    main()
    time.sleep(3)
    subprocess.run(["python","localpolicies.py"])
