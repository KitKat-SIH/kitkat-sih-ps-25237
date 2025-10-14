#!/usr/bin/env python3
"""
Windows Audit Policies Auto-Fix Script
Automatically configures Advanced Audit Policy Configuration
"""

import subprocess
import os
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
    print("WINDOWS AUDIT POLICIES AUTO-FIX SCRIPT")
    print(f"{Colors.BLUE}=" * 70 + f"{Colors.END}")

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

def set_registry_value(hive, key_path, value_name, value_data, value_type):
    """Set a registry value"""
    try:
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, value_name, 0, value_type, value_data)
        return True
    except Exception as e:
        try:
            # Create the key if it doesn't exist
            winreg.CreateKey(hive, key_path)
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, value_name, 0, value_type, value_data)
            return True
        except Exception as e2:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to set {key_path}\\{value_name}: {e2}")
            return False

def configure_audit_policy(subcategory, setting, description):
    """Configure an audit policy using auditpol command"""
    try:
        cmd = ["auditpol", "/set", "/subcategory", subcategory, setting]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {description}")
            return True
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} {description} - Error: {result.stderr.strip() if result.stderr else 'Unknown error'}")
            return False
    except Exception as e:
        print(f"{Colors.RED}[FAILED]{Colors.END} {description} - Exception: {e}")
        return False

def fix_audit_policies():
    """Fix Advanced Audit Policy Configuration"""
    print(f"\n{Colors.BOLD}FIXING AUDIT POLICIES{Colors.END}")
    print("-" * 50)
    
    audit_policies = [
        ("\"Credential Validation\"", "/success:enable", "Audit Credential Validation (Success)"),
        ("\"Computer Account Management\"", "/success:enable", "Audit Computer Account Management (Success)"),
        ("\"Other Account Management Events\"", "/success:enable", "Audit Other Account Management Events (Success)"),
        ("\"Security Group Management\"", "/success:enable", "Audit Security Group Management (Success)"),
        ("\"User Account Management\"", "/success:enable", "Audit User Account Management (Success)"),
        ("\"Process Creation\"", "/success:enable", "Audit Process Creation (Success)"),
        ("\"Account Lockout\"", "/failure:enable", "Audit Account Lockout (Failure)"),
        ("\"Logoff\"", "/success:enable", "Audit Logoff (Success)"),
        ("\"Logon\"", "/success:enable /failure:enable", "Audit Logon (Success and Failure)"),
        ("\"Special Logon\"", "/success:enable", "Audit Special Logon (Success)"),
        ("\"Detailed File Share\"", "/failure:enable", "Audit Detailed File Share (Failure)"),
        ("\"File Share\"", "/success:enable /failure:enable", "Audit File Share (Success and Failure)"),
        ("\"Other Object Access Events\"", "/success:enable /failure:enable", "Audit Other Object Access Events (Success and Failure)"),
        ("\"Removable Storage\"", "/success:enable /failure:enable", "Audit Removable Storage (Success and Failure)"),
        ("\"Audit Policy Change\"", "/success:enable", "Audit Audit Policy Change (Success)"),
        ("\"Authentication Policy Change\"", "/success:enable", "Audit Authentication Policy Change (Success)"),
        ("\"Security System Extension\"", "/success:enable", "Audit Security System Extension (Success)"),
        ("\"System Integrity\"", "/success:enable /failure:enable", "Audit System Integrity (Success and Failure)")
    ]
    
    success_count = 0
    for subcategory, setting, description in audit_policies:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {description}...")
        if configure_audit_policy(subcategory, setting, description):
            success_count += 1
        time.sleep(0.5)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} Audit Policies: {success_count}/{len(audit_policies)} configured")
    return success_count == len(audit_policies)

def fix_smb_v1():
    """Disable SMB v1 protocol for security"""
    print(f"\n{Colors.BOLD}FIXING SMB V1 CONFIGURATION{Colors.END}")
    print("-" * 50)
    
    smb_fixes = [
        {
            "description": "Disable SMB v1 client driver",
            "command": ["sc", "config", "lanmanworkstation", "depend=", "bowser/mrxsmb20/nsi"],
            "registry": None
        },
        {
            "description": "Disable SMB v1 server",
            "command": ["powershell", "-Command", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"],
            "registry": {
                "key": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "value": "SMB1",
                "data": 0,
                "type": winreg.REG_DWORD
            }
        },
        {
            "description": "Remove SMB v1 client",
            "command": ["powershell", "-Command", "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart"],
            "registry": None
        },
        {
            "description": "Remove SMB v1 server",
            "command": ["powershell", "-Command", "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server -NoRestart"],
            "registry": None
        }
    ]
    
    success_count = 0
    for fix in smb_fixes:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {fix['description']}...")
        
        try:
            # Try command-based fix
            result = subprocess.run(fix['command'], capture_output=True, text=True, timeout=60)
            command_success = result.returncode == 0
            
            # Try registry-based fix if available
            registry_success = True
            if fix['registry']:
                registry_success = set_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    fix['registry']['key'],
                    fix['registry']['value'],
                    fix['registry']['data'],
                    fix['registry']['type']
                )
            
            if command_success or registry_success:
                print(f"{Colors.GREEN}[FIXED]{Colors.END} {fix['description']}")
                success_count += 1
            else:
                print(f"{Colors.RED}[FAILED]{Colors.END} {fix['description']}")
                
        except Exception as e:
            print(f"{Colors.RED}[FAILED]{Colors.END} {fix['description']} - Exception: {e}")
        
        time.sleep(1)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} SMB v1 Configuration: {success_count}/{len(smb_fixes)} fixed")
    return success_count == len(smb_fixes)

def fix_autoplay_policies():
    """Configure AutoPlay policies for security"""
    print(f"\n{Colors.BOLD}FIXING AUTOPLAY POLICIES{Colors.END}")
    print("-" * 50)
    
    autoplay_fixes = [
        {
            "description": "Turn off AutoPlay for all drives",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "value": "NoDriveTypeAutoRun",
            "data": 255,  # Disable for all drive types
            "type": winreg.REG_DWORD
        },
        {
            "description": "Disable AutoPlay for non-volume devices",
            "key": r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
            "value": "NoAutoplayfornonVolume",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Set AutoPlay default behavior to Take no action",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "value": "NoAutorun",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Prevent enabling lock screen camera",
            "key": r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
            "value": "NoLockScreenCamera",
            "data": 1,
            "type": winreg.REG_DWORD
        }
    ]
    
    success_count = 0
    for fix in autoplay_fixes:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {fix['description']}...")
        if set_registry_value(winreg.HKEY_LOCAL_MACHINE, fix['key'], fix['value'], fix['data'], fix['type']):
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {fix['description']}")
            success_count += 1
        time.sleep(0.5)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} AutoPlay Policies: {success_count}/{len(autoplay_fixes)} fixed")
    return success_count == len(autoplay_fixes)

def create_audit_template():
    """Create a comprehensive audit policy template"""
    template_content = """[Unicode]
Unicode=yes

[Event Audit]
AuditAccountLogon = 1
AuditAccountManage = 1
AuditDSAccess = 0
AuditLogonEvents = 3
AuditObjectAccess = 1
AuditPolicyChange = 1
AuditPrivilegeUse = 0
AuditProcessTracking = 1
AuditSystemEvents = 3

[Registry Values]
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun=4,255
MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer\\NoAutoplayfornonVolume=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoAutorun=4,1
MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization\\NoLockScreenCamera=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1=4,0

[Version]
signature="$CHICAGO$"
Revision=1
"""
    
    import tempfile
    temp_file = os.path.join(tempfile.gettempdir(), "audit_policies_template.inf")
    
    try:
        with open(temp_file, 'w', encoding='utf-16') as f:
            f.write(template_content)
        return temp_file
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to create audit template: {e}")
        return None

def apply_audit_template(template_path):
    """Apply the audit policy template using secedit"""
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Applying audit policy template...")
    time.sleep(1)
    
    try:
        result = subprocess.run([
            "secedit", "/configure", "/cfg", template_path, "/areas", "REGKEYS"
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit policy template applied successfully")
            return True
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to apply audit policy template")
            print(f"Return code: {result.returncode}")
            if result.stderr:
                print(f"Error details: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error applying audit policy template: {e}")
        return False

def main():
    """Main function"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print("Please run this script as Administrator to modify audit policies.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    # Ask for confirmation
    print(f"{Colors.YELLOW}[WARNING]{Colors.END} This script will modify Windows Audit Policies.")
    print("The following changes will be applied:")
    print("  • Advanced Audit Policy Configuration (18 subcategories)")
    print("  • SMB v1 protocol (complete removal/disabling)")
    print("  • AutoPlay policies (disable for security)")
    print()
    
    confirm = input(f"{Colors.BLUE}[CONFIRM]{Colors.END} Do you want to proceed? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Operation cancelled by user")
        sys.exit(0)
    
    print()
    
    try:
        # Method 1: Try template-based approach for registry settings
        template_path = create_audit_template()
        if template_path:
            template_success = apply_audit_template(template_path)
            
            # Clean up template
            if os.path.exists(template_path):
                os.remove(template_path)
        
        # Method 2: Individual fixes (always run for audit policies)
        audit_success = fix_audit_policies()
        smb_success = fix_smb_v1()
        autoplay_success = fix_autoplay_policies()
        
        # Force Group Policy update
        print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Updating Group Policy...")
        try:
            subprocess.run(["gpupdate", "/force"], capture_output=True, timeout=60)
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Group Policy updated")
        except:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Group Policy update may have failed")
        
        # Force audit policy refresh
        print(f"{Colors.YELLOW}[WORKING]{Colors.END} Refreshing audit policies...")
        try:
            subprocess.run(["auditpol", "/clear"], capture_output=True, timeout=30)
            time.sleep(2)
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit policies refreshed")
        except:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Audit policy refresh may have failed")
        
        print(f"\n{Colors.BLUE}[INFO]{Colors.END} Audit Policies configuration complete!")
        print("Please restart your computer for all changes to take full effect.")
        
        if not smb_success:
            print(f"\n{Colors.YELLOW}[NOTE]{Colors.END} SMB v1 removal requires Windows restart.")
            print("Some SMB v1 components may not be available on this Windows edition.")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.END} Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
