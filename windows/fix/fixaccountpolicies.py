#!/usr/bin/env python3
"""
Windows Account Policies Auto-Fix Script
Automatically configures password and account lockout policies to meet security requirements
"""

import subprocess
import os
import re
import platform
import ctypes
import sys
import time
import tempfile

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
    print("WINDOWS ACCOUNT POLICIES AUTO-FIX SCRIPT")
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
        print(f"Current OS: {platform.system()}")
        sys.exit(1)

def create_security_template():
    """Create a security template file with compliant settings"""
    template_content = """[Unicode]
Unicode=yes

[System Access]
; Password Policy Settings
PasswordHistorySize = 24
MaximumPasswordAge = 90
MinimumPasswordAge = 1
MinimumPasswordLength = 12
PasswordComplexity = 1
ClearTextPassword = 0

; Account Lockout Policy Settings
LockoutDuration = 15
LockoutBadCount = 3

[Version]
signature="$CHICAGO$"
Revision=1
"""
    
    # Create temporary template file
    temp_dir = tempfile.gettempdir()
    template_path = os.path.join(temp_dir, "security_template.inf")
    
    try:
        with open(template_path, 'w', encoding='utf-16') as f:
            f.write(template_content)
        return template_path
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to create security template: {e}")
        return None

def apply_security_template(template_path):
    """Apply the security template using secedit"""
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Applying security policy template...")
    time.sleep(1)
    
    try:
        # Apply the security template
        result = subprocess.run([
            "secedit", "/configure", "/cfg", template_path, "/overwrite"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Security template applied successfully")
            return True
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to apply security template")
            print(f"Return code: {result.returncode}")
            if result.stderr:
                print(f"Error details: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}[ERROR]{Colors.END} Security template application timed out")
        return False
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error applying security template: {e}")
        return False

def fix_password_policies():
    """Fix password policies using multiple methods"""
    print(f"\n{Colors.BOLD}FIXING PASSWORD POLICIES{Colors.END}")
    print("-" * 50)
    
    success_count = 0
    
    # Method 1: Use net accounts command
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Password History...")
    try:
        result = subprocess.run(["net", "accounts", "/uniquepw:24"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Password History set to 24")
            success_count += 1
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Password History")
    except:
        print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Password History")
    
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Maximum Password Age...")
    try:
        result = subprocess.run(["net", "accounts", "/maxpwage:90"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Maximum Password Age set to 90 days")
            success_count += 1
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Maximum Password Age")
    except:
        print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Maximum Password Age")
    
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Minimum Password Age...")
    try:
        result = subprocess.run(["net", "accounts", "/minpwage:1"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Minimum Password Age set to 1 day")
            success_count += 1
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Minimum Password Age")
    except:
        print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Minimum Password Age")
    
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Minimum Password Length...")
    try:
        result = subprocess.run(["net", "accounts", "/minpwlen:12"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Minimum Password Length set to 12")
            success_count += 1
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Minimum Password Length")
    except:
        print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Minimum Password Length")
    
    # Method 2: Use PowerShell for password complexity
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Password Complexity...")
    try:
        result = subprocess.run([
            "powershell", "-Command",
            "secedit /export /cfg c:\\temp_sec.inf; " +
            "(Get-Content c:\\temp_sec.inf) -replace '^PasswordComplexity.*', 'PasswordComplexity = 1' | Set-Content c:\\temp_sec.inf; " +
            "secedit /configure /cfg c:\\temp_sec.inf /areas SECURITYPOLICY; " +
            "Remove-Item c:\\temp_sec.inf -ErrorAction SilentlyContinue"
        ], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Password Complexity enabled")
            success_count += 1
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Password Complexity")
    except:
        print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Password Complexity")
    
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Reversible Encryption...")
    try:
        result = subprocess.run([
            "powershell", "-Command",
            "secedit /export /cfg c:\\temp_sec.inf; " +
            "(Get-Content c:\\temp_sec.inf) -replace '^ClearTextPassword.*', 'ClearTextPassword = 0' | Set-Content c:\\temp_sec.inf; " +
            "secedit /configure /cfg c:\\temp_sec.inf /areas SECURITYPOLICY; " +
            "Remove-Item c:\\temp_sec.inf -ErrorAction SilentlyContinue"
        ], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Reversible Encryption disabled")
            success_count += 1
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Reversible Encryption")
    except:
        print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Reversible Encryption")
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} Password Policies: {success_count}/6 fixed")
    return success_count == 6

def fix_account_lockout_policies():
    """Fix account lockout policies"""
    print(f"\n{Colors.BOLD}FIXING ACCOUNT LOCKOUT POLICIES{Colors.END}")
    print("-" * 50)
    
    success_count = 0
    
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Account Lockout Duration...")
    try:
        result = subprocess.run(["net", "accounts", "/lockoutduration:15"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Account Lockout Duration set to 15 minutes")
            success_count += 1
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Account Lockout Duration")
    except:
        print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Account Lockout Duration")
    
    print(f"{Colors.YELLOW}[FIXING]{Colors.END} Account Lockout Threshold...")
    try:
        result = subprocess.run(["net", "accounts", "/lockoutthreshold:3"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} Account Lockout Threshold set to 3 attempts")
            success_count += 1
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Account Lockout Threshold")
    except:
        print(f"{Colors.RED}[FAILED]{Colors.END} Could not fix Account Lockout Threshold")
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} Account Lockout Policies: {success_count}/2 fixed")
    return success_count == 2

def apply_group_policy_updates():
    """Force Group Policy update to ensure changes take effect"""
    print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Applying Group Policy updates...")
    time.sleep(1)
    
    try:
        # Force Group Policy update
        result = subprocess.run([
            "gpupdate", "/force"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Group Policy updated successfully")
            return True
        else:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Group Policy update completed with warnings")
            return True
            
    except subprocess.TimeoutExpired:
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} Group Policy update timed out")
        return False
    except Exception as e:
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} Error updating Group Policy: {e}")
        return False

def verify_changes():
    """Verify that the changes were applied successfully"""
    print(f"\n{Colors.BOLD}VERIFYING APPLIED CHANGES{Colors.END}")
    print("-" * 50)
    
    # Export current policy to verify
    temp_path = os.path.join(tempfile.gettempdir(), "verify_policy.inf")
    
    try:
        result = subprocess.run([
            "secedit", "/export", "/cfg", temp_path, "/quiet"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0 or not os.path.exists(temp_path):
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Could not export policy for verification")
            return False
        
        # Read and parse the exported policy
        try:
            with open(temp_path, "r", encoding="utf-16") as f:
                policy_data = f.read()
        except UnicodeError:
            with open(temp_path, "r") as f:
                policy_data = f.read()
        
        # Verify key settings
        verifications = {
            "PasswordHistorySize": "24",
            "MaximumPasswordAge": "90", 
            "MinimumPasswordAge": "1",
            "MinimumPasswordLength": "12",
            "PasswordComplexity": "1",
            "ClearTextPassword": "0",
            "LockoutDuration": "15",
            "LockoutBadCount": "3"
        }
        
        verified_count = 0
        total_verifications = len(verifications)
        
        for policy_key, expected_value in verifications.items():
            pattern = rf"^{policy_key}\s*=\s*(\S+)"
            match = re.search(pattern, policy_data, re.MULTILINE | re.IGNORECASE)
            
            if match and match.group(1) == expected_value:
                print(f"{Colors.GREEN}[VERIFIED]{Colors.END} {policy_key} = {expected_value}")
                verified_count += 1
            else:
                current_value = match.group(1) if match else "Not Found"
                print(f"{Colors.RED}[FAILED]{Colors.END} {policy_key} = {current_value} (expected {expected_value})")
        
        # Clean up verification file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        print(f"\n{Colors.BLUE}[VERIFICATION]{Colors.END} {verified_count}/{total_verifications} policies verified")
        return verified_count == total_verifications
        
    except Exception as e:
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} Error during verification: {e}")
        return False

def create_backup():
    """Create a backup of current security settings"""
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Creating backup of current security settings...")
    time.sleep(1)
    
    backup_path = os.path.join(os.getcwd(), f"security_backup_{int(time.time())}.inf")
    
    try:
        result = subprocess.run([
            "secedit", "/export", "/cfg", backup_path
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and os.path.exists(backup_path):
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Backup created: {backup_path}")
            return backup_path
        else:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Could not create backup")
            return None
            
    except Exception as e:
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} Error creating backup: {e}")
        return None

def main():
    """Main function to orchestrate the fixing process"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print("Please run this script as Administrator to modify security policies.")
        print("\nTo run as Administrator:")
        print("1. Right-click on Command Prompt or PowerShell")
        print("2. Select 'Run as Administrator'")
        print("3. Navigate to script directory and run again")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    # Ask for confirmation
    print(f"{Colors.YELLOW}[WARNING]{Colors.END} This script will modify Windows security policies.")
    print("The following changes will be applied:")
    print("  • Password history: 24 passwords")
    print("  • Maximum password age: 90 days")
    print("  • Minimum password age: 1 day")
    print("  • Minimum password length: 12 characters")
    print("  • Password complexity: Enabled")
    print("  • Reversible encryption: Disabled")
    print("  • Account lockout duration: 15 minutes")
    print("  • Account lockout threshold: 3 attempts")
    print()
    
    confirm = input(f"{Colors.BLUE}[CONFIRM]{Colors.END} Do you want to proceed? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Operation cancelled by user")
        sys.exit(0)
    
    print()
    
    try:
        # Create backup
        backup_path = create_backup()
        
        # Fix password policies
        password_success = fix_password_policies()
        
        # Fix account lockout policies  
        lockout_success = fix_account_lockout_policies()
        
        # Apply Group Policy updates
        gp_success = apply_group_policy_updates()
        
        # Verify changes
        print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Waiting for policies to take effect...")
        time.sleep(3)
        verify_success = verify_changes()
        
        # Final summary
        print(f"\n{Colors.BOLD}FINAL SUMMARY{Colors.END}")
        print("=" * 70)
        
        password_status = f"{Colors.GREEN}SUCCESS{Colors.END}" if password_success else f"{Colors.RED}FAILED{Colors.END}"
        lockout_status = f"{Colors.GREEN}SUCCESS{Colors.END}" if lockout_success else f"{Colors.RED}FAILED{Colors.END}"
        verification_status = f"{Colors.GREEN}SUCCESS{Colors.END}" if verify_success else f"{Colors.YELLOW}PARTIAL{Colors.END}"
        
        print(f"Password Policies Fix:        {password_status}")
        print(f"Account Lockout Policies Fix: {lockout_status}")
        print(f"Group Policy Update:          {f'{Colors.GREEN}SUCCESS{Colors.END}' if gp_success else f'{Colors.YELLOW}PARTIAL{Colors.END}'}")
        print(f"Verification:                 {verification_status}")
        
        if backup_path:
            print(f"\nBackup Location: {backup_path}")
        
        overall_success = password_success and lockout_success
        
        if overall_success:
            print(f"\n{Colors.GREEN}[COMPLETE]{Colors.END} Account policies have been successfully configured!")
            print("Your Windows system now meets the security policy requirements.")
        else:
            print(f"\n{Colors.YELLOW}[PARTIAL SUCCESS]{Colors.END} Some policies may need manual configuration.")
            print("Please review the output above and manually configure any failed policies.")
        
        print(f"\n{Colors.BLUE}[INFO]{Colors.END} It's recommended to:")
        print("1. Restart your computer for all changes to take full effect")
        print("2. Test user login functionality")
        print("3. Run the account policies checker to verify compliance")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.END} Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
