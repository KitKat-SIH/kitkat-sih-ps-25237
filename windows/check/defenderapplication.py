#!/usr/bin/env python3
"""
Microsoft Defender Application Guard Security Checker
Verifies Application Guard policy compliance according to security standards
"""

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
    print("CHECKING MICROSOFT DEFENDER APPLICATION GUARD")
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
    except (FileNotFoundError, OSError):
        return None

def check_application_guard_feature():
    """Check if Microsoft Defender Application Guard feature is available"""
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Checking Application Guard feature availability...")
    time.sleep(1)
    
    # Method 1: Check via Windows Features using DISM
    try:
        result = subprocess.run(
            ["dism", "/online", "/get-features", "/format:table"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            output = result.stdout.lower()
            if "windows-defender-applicationguard" in output:
                if "enabled" in output:
                    print(f"{Colors.GREEN}[INFO]{Colors.END} Microsoft Defender Application Guard feature is enabled")
                    return True
                else:
                    print(f"{Colors.YELLOW}[WARNING]{Colors.END} Microsoft Defender Application Guard feature is not enabled")
                    print(f"                Enable with: dism /online /enable-feature /featurename:Windows-Defender-ApplicationGuard")
                    return False
            else:
                print(f"{Colors.YELLOW}[WARNING]{Colors.END} Microsoft Defender Application Guard feature not found")
                return False
    except Exception as e:
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} Could not check Application Guard feature status: {e}")
    
    # Method 2: Check via PowerShell as fallback
    try:
        result = subprocess.run([
            "powershell", "-Command", 
            "Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard | Select-Object State"
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            if "enabled" in output:
                print(f"{Colors.GREEN}[INFO]{Colors.END} Microsoft Defender Application Guard feature is enabled")
                return True
            else:
                print(f"{Colors.YELLOW}[WARNING]{Colors.END} Microsoft Defender Application Guard feature is not enabled")
                return False
    except Exception:
        pass
    
    print(f"{Colors.YELLOW}[WARNING]{Colors.END} Could not determine Application Guard feature status")
    return False

def check_application_guard_policies():
    """Check Microsoft Defender Application Guard policy configuration"""
    print(f"\n{Colors.BOLD}MICROSOFT DEFENDER APPLICATION GUARD POLICIES{Colors.END}")
    print("-" * 80)
    
    # Application Guard policy registry paths and settings
    ag_checks = {
        "AuditApplicationGuard": {
            "description": "Allow auditing events in Microsoft Defender Application Guard",
            "requirement": "Enabled",
            "registry_path": r"Software\Policies\Microsoft\AppHVSI",
            "registry_value": "AuditApplicationGuard",
            "expected_value": "1",
            "check_type": "exact"
        },
        "AllowCameraMicrophoneRedirection": {
            "description": "Allow camera and microphone access in Microsoft Defender Application Guard",
            "requirement": "Disabled",
            "registry_path": r"Software\Policies\Microsoft\AppHVSI",
            "registry_value": "AllowCameraMicrophoneRedirection",
            "expected_value": "0",
            "check_type": "exact"
        },
        "AllowPersistence": {
            "description": "Allow data persistence for Microsoft Defender Application Guard",
            "requirement": "Disabled",
            "registry_path": r"Software\Policies\Microsoft\AppHVSI",
            "registry_value": "AllowPersistence",
            "expected_value": "0",
            "check_type": "exact"
        },
        "SaveFilesToHost": {
            "description": "Allow files to download and save to the host operating system",
            "requirement": "Disabled",
            "registry_path": r"Software\Policies\Microsoft\AppHVSI",
            "registry_value": "SaveFilesToHost",
            "expected_value": "0",
            "check_type": "exact"
        },
        "AppHVSIClipboardSettings": {
            "description": "Configure clipboard settings - Enable clipboard operation from isolated session to host",
            "requirement": "Enabled: Enable clipboard operation from an isolated session to the host",
            "registry_path": r"Software\Policies\Microsoft\AppHVSI",
            "registry_value": "AppHVSIClipboardSettings",
            "expected_value": "1",
            "check_type": "exact"
        }
    }
    
    compliant_count = 0
    total_checks = len(ag_checks)
    
    for policy_key, config in ag_checks.items():
        # Get current registry value
        current_value = get_registry_value("HKLM", config["registry_path"], config["registry_value"])
        expected_value = config["expected_value"]
        
        # Check compliance
        is_compliant = False
        status_detail = ""
        
        if config["check_type"] == "exact":
            if current_value == expected_value:
                is_compliant = True
                status_detail = f"Current: Configured correctly, Required: {config['requirement']}"
            elif current_value == "0" and expected_value == "1":
                status_detail = f"Current: Disabled, Required: {config['requirement']}"
            elif current_value == "1" and expected_value == "0":
                status_detail = f"Current: Enabled, Required: {config['requirement']}"
            elif current_value is None:
                status_detail = f"Current: Not Configured, Required: {config['requirement']}"
            else:
                status_detail = f"Current: {current_value}, Required: {config['requirement']}"
        
        # Display result
        if current_value is None:
            status_icon = f"{Colors.YELLOW}[NOT CONFIGURED]{Colors.END}"
        elif is_compliant:
            status_icon = f"{Colors.GREEN}[COMPLIANT]{Colors.END}"
        else:
            status_icon = f"{Colors.RED}[NON-COMPLIANT]{Colors.END}"
        
        print(f"{status_icon} {config['description']}")
        print(f"               Required: {config['requirement']}")
        print(f"               Status: {status_detail}")
        
        # Show registry fix command if not compliant
        if not is_compliant:
            reg_path = f"HKLM\\{config['registry_path']}"
            reg_value = config['registry_value']
            reg_data = config['expected_value']
            print(f"               Fix: reg add \"{reg_path}\" /v {reg_value} /t REG_DWORD /d {reg_data} /f")
        
        print()
        
        if is_compliant:
            compliant_count += 1
    
    # Application Guard policies summary
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
    
    print(f"{summary_color}[{summary_status}]{Colors.END} Application Guard Policies Compliance: {compliant_count}/{total_checks} ({compliance_percentage:.1f}%)\n")
    
    return compliant_count == total_checks

def check_hyper_v_requirements():
    """Check if Hyper-V is available (required for Application Guard)"""
    print(f"\n{Colors.BOLD}HYPER-V REQUIREMENTS CHECK{Colors.END}")
    print("-" * 80)
    
    # Check if Hyper-V feature is enabled
    try:
        result = subprocess.run([
            "powershell", "-Command", 
            "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All | Select-Object State"
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            if "enabled" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Hyper-V is enabled")
                print(f"               Status: Application Guard can function properly")
                return True
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Hyper-V is not enabled")
                print(f"               Status: Application Guard requires Hyper-V to function")
                print(f"               Fix: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All")
                return False
    except Exception:
        pass
    
    # Fallback: Check via systeminfo
    try:
        result = subprocess.run(["systeminfo"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            output = result.stdout.lower()
            if "hyper-v requirements" in output:
                if "yes" in output:
                    print(f"{Colors.GREEN}[INFO]{Colors.END} System supports Hyper-V")
                    return True
                else:
                    print(f"{Colors.RED}[WARNING]{Colors.END} System may not support Hyper-V")
                    return False
    except Exception:
        pass
    
    print(f"{Colors.YELLOW}[UNKNOWN]{Colors.END} Could not determine Hyper-V status")
    return False

def main():
    """Main function to orchestrate the Application Guard checking"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print(f"Please run this script as Administrator")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    try:
        # Check prerequisites
        ag_feature_available = check_application_guard_feature()
        hyper_v_available = check_hyper_v_requirements()
        
        # Check Application Guard policies
        ag_policies_compliant = check_application_guard_policies()
        
        # Overall summary
        print(f"\n{Colors.BOLD}APPLICATION GUARD CONFIGURATION SUMMARY{Colors.END}")
        print(f"{Colors.BLUE}={'=' * 80}{Colors.END}")
        
        feature_status = f"{Colors.GREEN}AVAILABLE{Colors.END}" if ag_feature_available else f"{Colors.RED}NOT AVAILABLE{Colors.END}"
        hyperv_status = f"{Colors.GREEN}AVAILABLE{Colors.END}" if hyper_v_available else f"{Colors.RED}NOT AVAILABLE{Colors.END}"
        policies_status = f"{Colors.GREEN}COMPLIANT{Colors.END}" if ag_policies_compliant else f"{Colors.RED}NON-COMPLIANT{Colors.END}"
        
        print(f"Application Guard Feature:            {feature_status}")
        print(f"Hyper-V Support:                     {hyperv_status}")
        print(f"Application Guard Policies:          {policies_status}")
        
        overall_compliant = all([ag_feature_available, hyper_v_available, ag_policies_compliant])
        overall_status = f"{Colors.GREEN}FULLY COMPLIANT{Colors.END}" if overall_compliant else f"{Colors.RED}REQUIRES ATTENTION{Colors.END}"
        
        print(f"\nOverall Application Guard Status:    {overall_status}")
        
        if not overall_compliant:
            print(f"\n{Colors.YELLOW}[REMEDIATION STEPS]{Colors.END}")
            
            if not hyper_v_available:
                print("1. Enable Hyper-V (required for Application Guard):")
                print("   Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All")
                print()
            
            if not ag_feature_available:
                print("2. Enable Microsoft Defender Application Guard:")
                print("   dism /online /enable-feature /featurename:Windows-Defender-ApplicationGuard")
                print("   OR via PowerShell:")
                print("   Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard")
                print()
            
            if not ag_policies_compliant:
                print("3. Configure Application Guard policies via Group Policy:")
                print("   Computer Configuration > Administrative Templates > Windows Components")
                print("   > Microsoft Defender Application Guard")
                print()
                print("   OR apply registry settings shown above for each non-compliant policy")
                print()
            
            print("4. Restart the computer after enabling features")
            print("5. Run this script again to verify compliance")
        
        else:
            print(f"\n{Colors.GREEN}[SUCCESS]{Colors.END} Microsoft Defender Application Guard is properly configured!")
        
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error checking Application Guard configuration: {str(e)}")

if __name__ == "__main__":
    main()
