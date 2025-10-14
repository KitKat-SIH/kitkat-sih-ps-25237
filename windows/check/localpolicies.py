#!/usr/bin/env python3
import subprocess
import os
import re
import platform
import ctypes
import sys
import admin
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
    print("CHECKING WINDOWS LOCAL POLICIES")
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
    temp_path = os.path.join(cwd, "local_policies_export.inf")
    
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

def check_specific_user_right_via_ntrights(right_name):
    try:
        # Note: ntrights.exe is part of Windows Resource Kit, may not be available
        result = subprocess.run(
            ["ntrights", "-u", right_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None

def parse_policy_data(file_path):
    """Read and parse the exported policy file"""
    try:
        with open(file_path, "r", encoding="utf-16") as f:
            data = f.read()
    except UnicodeError:
        with open(file_path, "r") as f:
            data = f.read()
    return data

def normalize_account_names(accounts_string):
    if not accounts_string or accounts_string.strip() == "":
        return []
    
    accounts = [acc.strip() for acc in accounts_string.split(',')]
    
    normalized = []
    for account in accounts:
        # Remove domain prefixes and normalize
        account = account.replace('*S-1-5-32-544', 'Administrators')
        account = account.replace('*S-1-5-32-545', 'Users')
        account = account.replace('*S-1-5-32-555', 'Remote Desktop Users')
        account = account.replace('*S-1-5-19', 'LOCAL SERVICE')
        account = account.replace('*S-1-5-20', 'NETWORK SERVICE')
        
        if account.startswith('*S-1-'):
            continue  #skippp
            
        normalized.append(account)
    
    return sorted(normalized)

def check_user_rights_assignments(policy_data):
    
    rights_checks = {
        "SeTrustedCredManAccessPrivilege": {
            "description": "Access Credential Manager as a trusted caller",
            "requirement": "No One",
            "expected_accounts": [],
            "check_type": "exact_match",
            "default_if_missing": "compliant"  #if not available toh set no one hi assume kia
        },
        "SeNetworkLogonRight": {
            "description": "Access this computer from the network",
            "requirement": "Administrators, Remote Desktop Users",
            "expected_accounts": ["Administrators", "Remote Desktop Users"],
            "check_type": "exact_match",
            "default_if_missing": "check_manually"
        },
        "SeIncreaseQuotaPrivilege": {
            "description": "Adjust memory quotas for a process",
            "requirement": "Administrators, LOCAL SERVICE, NETWORK SERVICE",
            "expected_accounts": ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE"],
            "check_type": "exact_match",
            "default_if_missing": "check_manually"
        },
        "SeInteractiveLogonRight": {
            "description": "Allow log on locally",
            "requirement": "Administrators, Users",
            "expected_accounts": ["Administrators", "Users"],
            "check_type": "exact_match",
            "default_if_missing": "check_manually"
        },
        "SeBackupPrivilege": {
            "description": "Back up files and directories",
            "requirement": "Administrators",
            "expected_accounts": ["Administrators"],
            "check_type": "exact_match",
            "default_if_missing": "check_manually"
        },
        "SeSystemtimePrivilege": {
            "description": "Change the system time",
            "requirement": "Administrators, LOCAL SERVICE",
            "expected_accounts": ["Administrators", "LOCAL SERVICE"],
            "check_type": "exact_match",
            "default_if_missing": "check_manually"
        },
        "SeTimeZonePrivilege": {
            "description": "Change the time zone",
            "requirement": "Administrators, LOCAL SERVICE, Users",
            "expected_accounts": ["Administrators", "LOCAL SERVICE", "Users"],
            "check_type": "exact_match",
            "default_if_missing": "check_manually"
        }
    }
    
    print(f"\n{Colors.BOLD}USER RIGHTS ASSIGNMENT COMPLIANCE REPORT{Colors.END}")
    print("-" * 80)
    
    compliant_count = 0
    total_checks = len(rights_checks)
    manual_checks = 0
    
    # First, let's search for the [Privilege Rights] section
    privilege_section = re.search(r'\[Privilege Rights\](.*?)(?=\[|$)', policy_data, re.DOTALL | re.IGNORECASE)
    if privilege_section:
        privilege_data = privilege_section.group(1)
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Found Privilege Rights section in policy export")
    else:
        privilege_data = policy_data
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Using full policy data (no specific Privilege Rights section found)")
    
    for right_key, config in rights_checks.items():
        # Search for the user right in the exported data
        # Try multiple patterns as the format can vary
        patterns = [
            rf"^{right_key}\s*=\s*(.*?)$",
            rf"^\s*{right_key}\s*=\s*(.*?)$",
            rf"{right_key}\s*=\s*(.*?)(?:\r?\n|$)"
        ]
        
        match = None
        for pattern in patterns:
            match = re.search(pattern, privilege_data, re.MULTILINE | re.IGNORECASE)
            if match:
                break
        
        if not match:
            if config.get("default_if_missing") == "compliant":
                print(f"{Colors.GREEN}[ASSUMED COMPLIANT]{Colors.END} {config['description']}")
                print(f"               Required: {config['requirement']}")
                print(f"               Status: Not explicitly set (assuming default 'No One')")
                print(f"               Note: If this right was previously assigned, it would appear in export\n")
                compliant_count += 1
                continue
            elif config.get("default_if_missing") == "check_manually":
                print(f"{Colors.YELLOW}[MANUAL CHECK REQUIRED]{Colors.END} {config['description']}")
                print(f"               Required: {config['requirement']}")
                print(f"               Status: Not found in policy export - manual verification needed")
                print(f"               Action: Open secpol.msc > Local Policies > User Rights Assignment")
                print(f"                      and verify this setting manually\n")
                manual_checks += 1
                continue
            else:
                print(f"{Colors.RED}[NOT FOUND]{Colors.END} {config['description']}")
                print(f"               Required: {config['requirement']}")
                print(f"               Status: User right not found in policy export\n")
                continue
        
        # Get the current accounts assigned to this right
        current_accounts_raw = match.group(1).strip()
        current_accounts = normalize_account_names(current_accounts_raw)
        expected_accounts = sorted(config["expected_accounts"])
        
        # Check compliance
        is_compliant = False
        status_detail = ""
        
        if config["check_type"] == "exact_match":
            is_compliant = current_accounts == expected_accounts
            
            if not current_accounts and not expected_accounts:
                status_detail = "Current: No One, Required: No One"
            elif not current_accounts:
                status_detail = f"Current: No One, Required: {', '.join(expected_accounts)}"
            elif not expected_accounts:
                status_detail = f"Current: {', '.join(current_accounts)}, Required: No One"
            else:
                status_detail = f"Current: {', '.join(current_accounts)}, Required: {', '.join(expected_accounts)}"
        
        status_icon = f"{Colors.GREEN}[COMPLIANT]{Colors.END}" if is_compliant else f"{Colors.RED}[NON-COMPLIANT]{Colors.END}"
        
        print(f"{status_icon} {config['description']}")
        print(f"               Required: {config['requirement']}")
        print(f"               Status: {status_detail}")
        print()
        
        if is_compliant:
            compliant_count += 1
    
    # Summary
    automated_checks = total_checks - manual_checks
    compliance_percentage = (compliant_count / automated_checks) * 100 if automated_checks > 0 else 0
    
    if compliant_count == automated_checks and manual_checks == 0:
        summary_color = Colors.GREEN
        summary_status = "FULLY COMPLIANT"
    elif compliant_count >= automated_checks * 0.8:
        summary_color = Colors.YELLOW
        summary_status = "MOSTLY COMPLIANT"
    elif manual_checks > 0:
        summary_color = Colors.YELLOW
        summary_status = "REQUIRES MANUAL VERIFICATION"
    else:
        summary_color = Colors.RED
        summary_status = "NON-COMPLIANT"
    
    print(f"{summary_color}[{summary_status}]{Colors.END} User Rights Assignment Compliance")
    print(f"Automated checks - Compliant: {compliant_count}/{automated_checks} ({compliance_percentage:.1f}%)")
    if manual_checks > 0:
        print(f"Manual verification required: {manual_checks} policies")
        print(f"{Colors.YELLOW}Note:{Colors.END} Some policies require manual verification in Local Security Policy")
    
    return (compliant_count == automated_checks) and (manual_checks == 0)

def cleanup_temp_files(file_path):
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
        admin.admin()
        sys.exit(1)
    temp_file = export_security_policy()
    if not temp_file:
        print(f"{Colors.RED}[FATAL]{Colors.END} Cannot proceed without security policy export")
        sys.exit(1)
    
    try:
        policy_data = parse_policy_data(temp_file)        
        rights_compliant = check_user_rights_assignments(policy_data)

        print(f"\n{Colors.BOLD}Local Policies Summary{Colors.END}")
        print(f"{Colors.BLUE}={Colors.END}" * 80)
        
        rights_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if rights_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        print(f"User Rights Assignments: {rights_status}")
        
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error processing policy data: {str(e)}")
    
    finally:
        cleanup_temp_files(temp_file)

if __name__ == "__main__":
    main()
    time.sleep(3)
    subprocess.run(["python","securityoptions.py"])
