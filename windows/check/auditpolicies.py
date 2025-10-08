#!/usr/bin/env python3
import subprocess
import os
import re
import platform
import ctypes
import sys
import time
import winreg

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
    print("CHECKING WINDOWS ADVANCED AUDIT POLICY CONFIGURATION")
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

def get_all_audit_policies():
    """Get all audit policies at once for better performance"""
    try:
        result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return result.stdout
        else:
            return None
    except Exception:
        return None

def parse_audit_status(audit_output, subcategory_name):
    """Parse audit status from the complete output"""
    if not audit_output:
        return "No Auditing"
    
    lines = audit_output.split('\n')
    for line in lines:
        # Look for the subcategory name in the line
        if subcategory_name.lower() in line.lower():
            line_lower = line.lower()
            if "success and failure" in line_lower:
                return "Success and Failure"
            elif "success" in line_lower and "failure" not in line_lower:
                return "Success"
            elif "failure" in line_lower and "success" not in line_lower:
                return "Failure"
            elif "no auditing" in line_lower:
                return "No Auditing"
    
    return "No Auditing"

def get_registry_value(hive, path, value_name):
    """Get a value from Windows registry"""
    try:
        # Convert hive string to registry constant
        if hive == "HKLM" or hive == "MACHINE":
            reg_hive = winreg.HKEY_LOCAL_MACHINE
        elif hive == "HKCU":
            reg_hive = winreg.HKEY_CURRENT_USER
        else:
            return None
        
        with winreg.OpenKey(reg_hive, path) as key:
            value, reg_type = winreg.QueryValueEx(key, value_name)
            return str(value)
    except (FileNotFoundError, OSError, WindowsError):
        return None

def check_smb_v1_status():
    """Check SMB v1 status using multiple methods"""
    results = {}
    
    # Method 1: Check via Windows Features
    try:
        result = subprocess.run(
            ["dism", "/online", "/get-features", "/format:table"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            output = result.stdout.lower()
            if "smb1protocol" in output:
                if "disabled" in output:
                    results["SMB1Protocol"] = "Disabled"
                elif "enabled" in output:
                    results["SMB1Protocol"] = "Enabled"
    except Exception:
        pass
    
    # Method 2: Check via PowerShell
    try:
        result = subprocess.run([
            "powershell", "-Command", 
            "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object State"
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            if "disabled" in output:
                results["SMB1Protocol_PS"] = "Disabled"
            elif "enabled" in output:
                results["SMB1Protocol_PS"] = "Enabled"
    except Exception:
        pass
    
    # Method 3: Check registry for SMB v1 server
    smb1_server = get_registry_value("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    if smb1_server is not None:
        results["SMB1Server"] = "Disabled" if smb1_server == "0" else "Enabled"
    
    return results

def check_advanced_audit_policies():
    """Check Advanced Audit Policy Configuration with improved detection"""
    print(f"\n{Colors.BOLD}ADVANCED AUDIT POLICY CONFIGURATION{Colors.END}")
    print("-" * 80)
    
    # Updated audit subcategory names that match Windows exactly
    audit_checks = {
        "Credential Validation": {
            "description": "Audit Credential Validation",
            "requirement": "Success and Failure",
            "expected_status": "Success and Failure"
        },
        "Application Group Management": {
            "description": "Audit Application Group Management", 
            "requirement": "Success and Failure",
            "expected_status": "Success and Failure"
        },
        "Security Group Management": {
            "description": "Audit Security Group Management",
            "requirement": "Success",
            "expected_status": ["Success", "Success and Failure"]
        },
        "User Account Management": {
            "description": "Audit User Account Management",
            "requirement": "Success and Failure",
            "expected_status": "Success and Failure"
        },
        "Plug and Play Events": {  # Changed from "PNP Activity"
            "description": "Audit PNP Activity",
            "requirement": "Success",
            "expected_status": ["Success", "Success and Failure"]
        },
        "Process Creation": {
            "description": "Audit Process Creation",
            "requirement": "Success",
            "expected_status": ["Success", "Success and Failure"]
        },
        "Account Lockout": {
            "description": "Audit Account Lockout",
            "requirement": "Failure",
            "expected_status": ["Failure", "Success and Failure"]
        },
        "Other Logon/Logoff Events": {
            "description": "Audit Other Logon/Logoff Events",
            "requirement": "Success and Failure",
            "expected_status": "Success and Failure"
        },
        "File Share": {
            "description": "Audit File Share",
            "requirement": "Success and Failure",
            "expected_status": "Success and Failure"
        },
        "Removable Storage": {
            "description": "Audit Removable Storage",
            "requirement": "Success and Failure",
            "expected_status": "Success and Failure"
        },
        "Audit Policy Change": {
            "description": "Audit Audit Policy Change",
            "requirement": "Success",
            "expected_status": ["Success", "Success and Failure"]
        },
        "Other Policy Change Events": {
            "description": "Audit Other Policy Change Events",
            "requirement": "Failure",
            "expected_status": ["Failure", "Success and Failure"]
        },
        "Sensitive Privilege Use": {
            "description": "Audit Sensitive Privilege Use",
            "requirement": "Success and Failure",
            "expected_status": "Success and Failure"
        },
        "System Integrity": {
            "description": "Audit System Integrity",
            "requirement": "Success and Failure",
            "expected_status": "Success and Failure"
        }
    }
    
    compliant_count = 0
    total_checks = len(audit_checks)
    
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Checking advanced audit policies...")
    time.sleep(1)
    
    # Get all audit policies at once for better performance
    audit_output = get_all_audit_policies()
    
    if not audit_output:
        print(f"{Colors.RED}[ERROR]{Colors.END} Unable to retrieve audit policy information")
        return False
    
    for subcategory, config in audit_checks.items():
        # Parse the audit status from the complete output
        current_status = parse_audit_status(audit_output, subcategory)
        expected_status = config["expected_status"]
        
        # Handle both single expected status and list of acceptable statuses
        if isinstance(expected_status, list):
            is_compliant = current_status in expected_status
        else:
            is_compliant = current_status == expected_status
        
        # Display result
        if current_status == "No Auditing":
            status_icon = f"{Colors.YELLOW}[NEEDS CONFIGURATION]{Colors.END}"
        elif is_compliant:
            status_icon = f"{Colors.GREEN}[COMPLIANT]{Colors.END}"
        else:
            status_icon = f"{Colors.RED}[NON-COMPLIANT]{Colors.END}"
        
        # Format expected status for display
        if isinstance(expected_status, list):
            expected_display = " or ".join(expected_status)
        else:
            expected_display = expected_status
        
        print(f"{status_icon} {config['description']}")
        print(f"               Required: {config['requirement']}")
        print(f"               Status: Current: {current_status}, Required: {expected_display}")
        
        # Show auditpol command to fix if not compliant
        if not is_compliant:
            if config["expected_status"] == "Success and Failure":
                print(f"               Fix: auditpol /set /subcategory:\"{subcategory}\" /success:enable /failure:enable")
            elif "Success" in str(config["expected_status"]):
                print(f"               Fix: auditpol /set /subcategory:\"{subcategory}\" /success:enable")
            elif "Failure" in str(config["expected_status"]):
                print(f"               Fix: auditpol /set /subcategory:\"{subcategory}\" /failure:enable")
        
        print()
        
        if is_compliant:
            compliant_count += 1
    
    # Audit policies summary
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
    
    print(f"{summary_color}[{summary_status}]{Colors.END} Advanced Audit Policies Compliance: {compliant_count}/{total_checks} ({compliance_percentage:.1f}%)\n")
    
    return compliant_count == total_checks

def check_security_policies():
    """Check additional security policies using direct registry access"""
    print(f"\n{Colors.BOLD}ADDITIONAL SECURITY POLICIES{Colors.END}")
    print("-" * 80)
    
    compliant_count = 0
    total_checks = 2  # Changed to 2 since we only check 2 policies
    
    # Check lock screen camera policy
    camera_value = get_registry_value("HKLM", r"Software\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera")
    if camera_value == "1":
        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Prevent enabling lock screen camera")
        print(f"               Required: Enabled")
        print(f"               Status: Current: Enabled, Required: Enabled")
        compliant_count += 1
    elif camera_value == "0":
        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Prevent enabling lock screen camera")
        print(f"               Required: Enabled")
        print(f"               Status: Current: Disabled, Required: Enabled")
    else:
        print(f"{Colors.YELLOW}[NOT CONFIGURED]{Colors.END} Prevent enabling lock screen camera")
        print(f"               Required: Enabled")
        print(f"               Status: Current: Not Configured, Required: Enabled")
        print(f"               Fix: Set HKLM\\Software\\Policies\\Microsoft\\Windows\\Personalization\\NoLockScreenCamera to 1")
    print()
    
    # Check SMB v1 configuration
    smb_status = check_smb_v1_status()
    
    if smb_status:
        smb_compliant = any("disabled" in str(v).lower() for v in smb_status.values())
        if smb_compliant:
            print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} SMB v1 Configuration")
            print(f"               Required: Disabled")
            print(f"               Status: Current: Disabled, Required: Disabled")
            compliant_count += 1
        else:
            print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} SMB v1 Configuration")
            print(f"               Required: Disabled")
            print(f"               Status: Current: Enabled, Required: Disabled")
            print(f"               Fix: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
    else:
        print(f"{Colors.YELLOW}[UNKNOWN]{Colors.END} SMB v1 Configuration")
        print(f"               Required: Disabled")
        print(f"               Status: Current: Unknown, Required: Disabled")
    print()
    
    # Summary
    compliance_percentage = (compliant_count / total_checks) * 100
    
    if compliant_count == total_checks:
        summary_color = Colors.GREEN
        summary_status = "FULLY COMPLIANT"
    elif compliant_count >= 1:
        summary_color = Colors.YELLOW
        summary_status = "MOSTLY COMPLIANT"
    else:
        summary_color = Colors.RED
        summary_status = "NON-COMPLIANT"
    
    print(f"{summary_color}[{summary_status}]{Colors.END} Additional Security Policies Compliance: {compliant_count}/{total_checks} ({compliance_percentage:.1f}%)\n")
    
    return compliant_count == total_checks

def check_autoplay_policies():
    """Check AutoPlay security policies using direct registry access"""
    print(f"\n{Colors.BOLD}AUTOPLAY POLICIES{Colors.END}")
    print("-" * 80)
    
    compliant_count = 0
    total_checks = 3
    
    # Check AutoPlay for non-volume devices
    autoplay_nonvolume = get_registry_value("HKLM", r"Software\Policies\Microsoft\Windows\Explorer", "NoAutoplayfornonVolume")
    if autoplay_nonvolume == "1":
        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Disallow Autoplay for non-volume devices")
        print(f"               Required: Enabled")
        print(f"               Status: Current: Enabled, Required: Enabled")
        compliant_count += 1
    else:
        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Disallow Autoplay for non-volume devices")
        print(f"               Required: Enabled")
        print(f"               Status: Current: Not Configured, Required: Enabled")
        print(f"               Fix: Set HKLM\\Software\\Policies\\Microsoft\\Windows\\Explorer\\NoAutoplayfornonVolume to 1")
    print()
    
    # Check AutoRun behavior
    autorun_value = get_registry_value("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoAutorun")
    if autorun_value == "1":
        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Set the default behaviour for AutoRun")
        print(f"               Required: Do not execute any autorun commands")
        print(f"               Status: Current: Enabled, Required: Enabled")
        compliant_count += 1
    else:
        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Set the default behaviour for AutoRun")
        print(f"               Required: Do not execute any autorun commands")
        print(f"               Status: Current: Not Configured, Required: Enabled")
        print(f"               Fix: Set HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoAutorun to 1")
    print()
    
    # Check Turn off AutoPlay
    autoplay_drives = get_registry_value("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
    if autoplay_drives == "255":
        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Turn off Autoplay")
        print(f"               Required: All drives")
        print(f"               Status: Current: All drives disabled, Required: All drives")
        compliant_count += 1
    else:
        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Turn off Autoplay")
        print(f"               Required: All drives")
        print(f"               Status: Current: Not fully configured, Required: All drives")
        print(f"               Fix: Set HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun to 255")
    print()
    
    # AutoPlay policies summary
    compliance_percentage = (compliant_count / total_checks) * 100
    
    if compliant_count == total_checks:
        summary_color = Colors.GREEN
        summary_status = "FULLY COMPLIANT"
    elif compliant_count >= 2:
        summary_color = Colors.YELLOW
        summary_status = "MOSTLY COMPLIANT"
    else:
        summary_color = Colors.RED
        summary_status = "NON-COMPLIANT"
    
    print(f"{summary_color}[{summary_status}]{Colors.END} AutoPlay Policies Compliance: {compliant_count}/{total_checks} ({compliance_percentage:.1f}%)\n")
    
    return compliant_count == total_checks

def main():
    """Main function to orchestrate the audit policy checking"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print(f"Please run this script as Administrator")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    try:
        # Check all audit policy categories using improved methods
        audit_compliant = check_advanced_audit_policies()
        security_compliant = check_security_policies()
        autoplay_compliant = check_autoplay_policies()
        
        # Overall summary
        print(f"\n{Colors.BOLD}AUDIT POLICY CONFIGURATION SUMMARY{Colors.END}")
        print(f"{Colors.BLUE}={'=' * 80}{Colors.END}")
        
        audit_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if audit_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        security_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if security_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        autoplay_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if autoplay_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        
        print(f"Advanced Audit Policies:             {audit_status}")
        print(f"Additional Security Policies:        {security_status}")
        print(f"AutoPlay Policies:                   {autoplay_status}")
        
        overall_compliant = all([audit_compliant, security_compliant, autoplay_compliant])
        overall_status = f"{Colors.GREEN}FULLY COMPLIANT{Colors.END}" if overall_compliant else f"{Colors.RED}REQUIRES ATTENTION{Colors.END}"
        
        print(f"\nOverall Audit Configuration Status:  {overall_status}")
        
        if not overall_compliant:
            print(f"\n{Colors.YELLOW}[REMEDIATION COMMANDS]{Colors.END}")
            print("For registry-based policies, run these commands as Administrator:")
            print('reg add "HKLM\\Software\\Policies\\Microsoft\\Windows\\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f')
            print('reg add "HKLM\\Software\\Policies\\Microsoft\\Windows\\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f')
            print('reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f')
            print('reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f')
        
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error processing audit policy data: {str(e)}")

if __name__ == "__main__":
    main()