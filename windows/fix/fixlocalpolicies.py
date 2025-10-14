#!/usr/bin/env python3
"""
Windows Local Policies Auto-Fix Script
Automatically configures User Rights Assignments to meet security requirements
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
    print("WINDOWS LOCAL POLICIES AUTO-FIX SCRIPT")
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

def fix_user_rights_assignments():
    """Fix User Rights Assignments using ntrights utility and secedit"""
    print(f"\n{Colors.BOLD}FIXING USER RIGHTS ASSIGNMENTS{Colors.END}")
    print("-" * 50)
    
    # User rights that need to be configured
    rights_fixes = {
        "SeTrustedCredManAccessPrivilege": {
            "description": "Access Credential Manager as a trusted caller",
            "accounts": [],  # No one should have this right
            "action": "revoke_all"
        },
        "SeNetworkLogonRight": {
            "description": "Access this computer from the network", 
            "accounts": ["Administrators", "Remote Desktop Users"],
            "action": "set_exact"
        },
        "SeIncreaseQuotaPrivilege": {
            "description": "Adjust memory quotas for a process",
            "accounts": ["Administrators", "LOCAL SERVICE", "NETWORK SERVICE"],
            "action": "set_exact"
        },
        "SeInteractiveLogonRight": {
            "description": "Allow log on locally",
            "accounts": ["Administrators", "Users"],
            "action": "set_exact"
        },
        "SeBackupPrivilege": {
            "description": "Back up files and directories",
            "accounts": ["Administrators"],
            "action": "set_exact"
        },
        "SeSystemtimePrivilege": {
            "description": "Change the system time",
            "accounts": ["Administrators", "LOCAL SERVICE"],
            "action": "set_exact"
        },
        "SeTimeZonePrivilege": {
            "description": "Change the time zone",
            "accounts": ["Administrators", "LOCAL SERVICE", "Users"],
            "action": "set_exact"
        }
    }
    
    success_count = 0
    total_fixes = len(rights_fixes)
    
    for right_name, config in rights_fixes.items():
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {config['description']}...")
        
        try:
            if config["action"] == "revoke_all":
                # Remove all accounts from this right
                result = subprocess.run([
                    "powershell", "-Command", 
                    f"$secpol = [System.IO.Path]::GetTempFileName(); " +
                    f"secedit /export /cfg $secpol; " +
                    f"(Get-Content $secpol) -replace '^{right_name}.*', '{right_name} =' | Set-Content $secpol; " +
                    f"secedit /configure /cfg $secpol /areas USER_RIGHTS; " +
                    f"Remove-Item $secpol"
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print(f"{Colors.GREEN}[FIXED]{Colors.END} Removed all accounts from {config['description']}")
                    success_count += 1
                else:
                    print(f"{Colors.RED}[FAILED]{Colors.END} Could not configure {config['description']}")
            
            elif config["action"] == "set_exact":
                # Set exact accounts for this right using proper SIDs
                sid_mapping = {
                    "Administrators": "*S-1-5-32-544",
                    "Users": "*S-1-5-32-545", 
                    "Remote Desktop Users": "*S-1-5-32-555",
                    "LOCAL SERVICE": "*S-1-5-19",
                    "NETWORK SERVICE": "*S-1-5-20"
                }
                
                accounts_str = ",".join([sid_mapping.get(account, f"*{account}") for account in config["accounts"]])
                
                result = subprocess.run([
                    "powershell", "-Command", 
                    f"$secpol = [System.IO.Path]::GetTempFileName(); " +
                    f"secedit /export /cfg $secpol; " +
                    f"(Get-Content $secpol) -replace '^{right_name}.*', '{right_name} = {accounts_str}' | Set-Content $secpol; " +
                    f"secedit /configure /cfg $secpol /areas USER_RIGHTS; " +
                    f"Remove-Item $secpol"
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    accounts_display = ", ".join(config["accounts"])
                    print(f"{Colors.GREEN}[FIXED]{Colors.END} Set {config['description']} to: {accounts_display}")
                    success_count += 1
                else:
                    print(f"{Colors.RED}[FAILED]{Colors.END} Could not configure {config['description']}")
                    
        except Exception as e:
            print(f"{Colors.RED}[FAILED]{Colors.END} Error fixing {config['description']}: {e}")
        
        time.sleep(1)  # Small delay between fixes
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} User Rights Assignments: {success_count}/{total_fixes} fixed")
    return success_count == total_fixes

def create_user_rights_template():
    """Create a comprehensive security template for user rights"""
    template_content = """[Unicode]
Unicode=yes

[Privilege Rights]
SeTrustedCredManAccessPrivilege = 
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeBackupPrivilege = *S-1-5-32-544
SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544
SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545

[Version]
signature="$CHICAGO$"
Revision=1
"""
    
    import tempfile
    temp_file = os.path.join(tempfile.gettempdir(), "user_rights_template.inf")
    
    try:
        with open(temp_file, 'w', encoding='utf-16') as f:
            f.write(template_content)
        return temp_file
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to create user rights template: {e}")
        return None

def apply_user_rights_template(template_path):
    """Apply the user rights template using secedit"""
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Applying user rights template...")
    time.sleep(1)
    
    try:
        result = subprocess.run([
            "secedit", "/configure", "/cfg", template_path, "/areas", "USER_RIGHTS"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} User rights template applied successfully")
            return True
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to apply user rights template")
            print(f"Return code: {result.returncode}")
            if result.stderr:
                print(f"Error details: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error applying user rights template: {e}")
        return False

def main():
    """Main function"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print("Please run this script as Administrator to modify local policies.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    # Ask for confirmation
    print(f"{Colors.YELLOW}[WARNING]{Colors.END} This script will modify Windows User Rights Assignments.")
    print("The following changes will be applied:")
    print("  • Access Credential Manager: No One")
    print("  • Access computer from network: Administrators, Remote Desktop Users")
    print("  • Adjust memory quotas: Administrators, LOCAL SERVICE, NETWORK SERVICE")
    print("  • Allow log on locally: Administrators, Users")
    print("  • Back up files and directories: Administrators")
    print("  • Change system time: Administrators, LOCAL SERVICE")
    print("  • Change time zone: Administrators, LOCAL SERVICE, Users")
    print()
    
    confirm = input(f"{Colors.BLUE}[CONFIRM]{Colors.END} Do you want to proceed? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Operation cancelled by user")
        sys.exit(0)
    
    print()
    
    try:
        # Method 1: Try template-based approach
        template_path = create_user_rights_template()
        if template_path:
            template_success = apply_user_rights_template(template_path)
            
            # Clean up template
            if os.path.exists(template_path):
                os.remove(template_path)
            
            if template_success:
                print(f"\n{Colors.GREEN}[COMPLETE]{Colors.END} User Rights Assignments have been configured!")
            else:
                print(f"\n{Colors.YELLOW}[FALLBACK]{Colors.END} Template method failed, trying individual fixes...")
                # Method 2: Individual fixes
                individual_success = fix_user_rights_assignments()
        else:
            # Method 2: Individual fixes only
            individual_success = fix_user_rights_assignments()
        
        # Force Group Policy update
        print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Updating Group Policy...")
        try:
            subprocess.run(["gpupdate", "/force"], capture_output=True, timeout=60)
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Group Policy updated")
        except:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Group Policy update may have failed")
        
        print(f"\n{Colors.BLUE}[INFO]{Colors.END} User Rights Assignments configuration complete!")
        print("Please restart your computer for all changes to take full effect.")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.END} Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
