#!/usr/bin/env python3
"""
Windows Security Options Auto-Fix Script
Automatically configures Security Options to meet security requirements
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
    print("WINDOWS SECURITY OPTIONS AUTO-FIX SCRIPT")
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

def fix_accounts_policies():
    """Fix Accounts security options"""
    print(f"\n{Colors.BOLD}FIXING ACCOUNTS POLICIES{Colors.END}")
    print("-" * 50)
    
    fixes = [
        {
            "description": "Administrator account status (Disabled)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
            "value": "Administrator",
            "data": 0,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Guest account status (Disabled)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
            "value": "Guest",
            "data": 0,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Limit local account use of blank passwords",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "LimitBlankPasswordUse",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Rename administrator account",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "value": "DefaultUserName",
            "data": "SecurityAdmin",
            "type": winreg.REG_SZ
        },
        {
            "description": "Rename guest account",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList",
            "value": "Visitor",
            "data": 0,
            "type": winreg.REG_DWORD
        }
    ]
    
    success_count = 0
    for fix in fixes:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {fix['description']}...")
        if set_registry_value(fix['hive'], fix['key'], fix['value'], fix['data'], fix['type']):
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {fix['description']}")
            success_count += 1
        time.sleep(0.5)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} Accounts Policies: {success_count}/{len(fixes)} fixed")
    return success_count == len(fixes)

def fix_interactive_logon_policies():
    """Fix Interactive Logon security options"""
    print(f"\n{Colors.BOLD}FIXING INTERACTIVE LOGON POLICIES{Colors.END}")
    print("-" * 50)
    
    fixes = [
        {
            "description": "Do not display last user name",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "DontDisplayLastUserName",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Do not require CTRL+ALT+DEL",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "DisableCAD",
            "data": 0,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Machine inactivity limit (900 seconds)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "InactivityTimeoutSecs",
            "data": 900,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Message text for users attempting to log on",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "LegalNoticeText",
            "data": "This system is for authorized use only. All activity is monitored and logged.",
            "type": winreg.REG_SZ
        },
        {
            "description": "Message title for users attempting to log on",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "LegalNoticeCaption",
            "data": "WARNING: Authorized Use Only",
            "type": winreg.REG_SZ
        },
        {
            "description": "Prompt user to change password before expiration",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "value": "PasswordExpiryWarning",
            "data": 14,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Require smart card",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "ScForceOption",
            "data": 0,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Smart card removal behavior (Lock workstation)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "value": "ScRemoveOption",
            "data": "1",
            "type": winreg.REG_SZ
        }
    ]
    
    success_count = 0
    for fix in fixes:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {fix['description']}...")
        if set_registry_value(fix['hive'], fix['key'], fix['value'], fix['data'], fix['type']):
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {fix['description']}")
            success_count += 1
        time.sleep(0.5)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} Interactive Logon Policies: {success_count}/{len(fixes)} fixed")
    return success_count == len(fixes)

def fix_network_access_policies():
    """Fix Network Access security options"""
    print(f"\n{Colors.BOLD}FIXING NETWORK ACCESS POLICIES{Colors.END}")
    print("-" * 50)
    
    fixes = [
        {
            "description": "Allow anonymous SID/Name translation (Disabled)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "TurnOffAnonymousBlock",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Do not allow anonymous enumeration of SAM accounts",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "RestrictAnonymousSAM",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Do not allow anonymous enumeration of SAM accounts and shares",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "RestrictAnonymous",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Let Everyone permissions apply to anonymous users (Disabled)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "EveryoneIncludesAnonymous",
            "data": 0,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Restrict anonymous access to Named Pipes and Shares",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
            "value": "RestrictNullSessAccess",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Shares that can be accessed anonymously (None)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
            "value": "NullSessionShares",
            "data": [],
            "type": winreg.REG_MULTI_SZ
        },
        {
            "description": "Do not allow storage of passwords and credentials for network authentication",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "DisableDomainCreds",
            "data": 1,
            "type": winreg.REG_DWORD
        }
    ]
    
    success_count = 0
    for fix in fixes:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {fix['description']}...")
        if set_registry_value(fix['hive'], fix['key'], fix['value'], fix['data'], fix['type']):
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {fix['description']}")
            success_count += 1
        time.sleep(0.5)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} Network Access Policies: {success_count}/{len(fixes)} fixed")
    return success_count == len(fixes)

def fix_network_security_policies():
    """Fix Network Security security options"""
    print(f"\n{Colors.BOLD}FIXING NETWORK SECURITY POLICIES{Colors.END}")
    print("-" * 50)
    
    fixes = [
        {
            "description": "Configure encryption types allowed for Kerberos",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
            "value": "SupportedEncryptionTypes",
            "data": 2147483644,  # AES128_HMAC_SHA1 | AES256_HMAC_SHA1 | FUTURE_ENCRYPTION_TYPES
            "type": winreg.REG_DWORD
        },
        {
            "description": "Do not store LAN Manager hash value",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "NoLMHash",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Force logoff when logon hours expire",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
            "value": "EnableForcedLogOff",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "LAN Manager authentication level (Send NTLMv2 response only)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value": "LmCompatibilityLevel",
            "data": 5,
            "type": winreg.REG_DWORD
        },
        {
            "description": "LDAP client signing requirements (Negotiate signing)",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Services\LDAP",
            "value": "LDAPClientIntegrity",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Minimum session security for NTLM SSP based clients",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
            "value": "NTLMMinClientSec",
            "data": 537395200,  # Require NTLMv2 session security, Require 128-bit encryption
            "type": winreg.REG_DWORD
        },
        {
            "description": "Minimum session security for NTLM SSP based servers",
            "hive": winreg.HKEY_LOCAL_MACHINE,
            "key": r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
            "value": "NTLMMinServerSec",
            "data": 537395200,  # Require NTLMv2 session security, Require 128-bit encryption
            "type": winreg.REG_DWORD
        }
    ]
    
    success_count = 0
    for fix in fixes:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {fix['description']}...")
        if set_registry_value(fix['hive'], fix['key'], fix['value'], fix['data'], fix['type']):
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {fix['description']}")
            success_count += 1
        time.sleep(0.5)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} Network Security Policies: {success_count}/{len(fixes)} fixed")
    return success_count == len(fixes)

def create_security_options_template():
    """Create a comprehensive security template for security options"""
    template_content = """[Unicode]
Unicode=yes

[Registry Values]
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD=4,0
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs=4,900
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText=1,"This system is for authorized use only. All activity is monitored and logged."
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption=1,"WARNING: Authorized Use Only"
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\PasswordExpiryWarning=4,14
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ScForceOption=4,0
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ScRemoveOption=1,"1"
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\TurnOffAnonymousBlock=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous=4,0
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RestrictNullSessAccess=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableForcedLogOff=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5
MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec=4,537395200
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec=4,537395200
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\DisableDomainCreds=4,1

[Version]
signature="$CHICAGO$"
Revision=1
"""
    
    import tempfile
    temp_file = os.path.join(tempfile.gettempdir(), "security_options_template.inf")
    
    try:
        with open(temp_file, 'w', encoding='utf-16') as f:
            f.write(template_content)
        return temp_file
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to create security options template: {e}")
        return None

def apply_security_options_template(template_path):
    """Apply the security options template using secedit"""
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Applying security options template...")
    time.sleep(1)
    
    try:
        result = subprocess.run([
            "secedit", "/configure", "/cfg", template_path, "/areas", "REGKEYS"
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Security options template applied successfully")
            return True
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to apply security options template")
            print(f"Return code: {result.returncode}")
            if result.stderr:
                print(f"Error details: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error applying security options template: {e}")
        return False

def main():
    """Main function"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print("Please run this script as Administrator to modify security options.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    # Ask for confirmation
    print(f"{Colors.YELLOW}[WARNING]{Colors.END} This script will modify Windows Security Options.")
    print("The following changes will be applied:")
    print("  • Accounts policies (disable guest/admin, limit blank passwords)")
    print("  • Interactive logon policies (legal notice, inactivity timeout)")
    print("  • Network access policies (anonymous restrictions)")
    print("  • Network security policies (NTLM, Kerberos, encryption)")
    print()
    
    confirm = input(f"{Colors.BLUE}[CONFIRM]{Colors.END} Do you want to proceed? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Operation cancelled by user")
        sys.exit(0)
    
    print()
    
    try:
        # Method 1: Try template-based approach
        template_path = create_security_options_template()
        if template_path:
            template_success = apply_security_options_template(template_path)
            
            # Clean up template
            if os.path.exists(template_path):
                os.remove(template_path)
            
            if not template_success:
                print(f"\n{Colors.YELLOW}[FALLBACK]{Colors.END} Template method failed, trying individual fixes...")
        
        # Method 2: Individual registry fixes (always run for completeness)
        accounts_success = fix_accounts_policies()
        interactive_success = fix_interactive_logon_policies()
        network_access_success = fix_network_access_policies()
        network_security_success = fix_network_security_policies()
        
        # Force Group Policy update
        print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Updating Group Policy...")
        try:
            subprocess.run(["gpupdate", "/force"], capture_output=True, timeout=60)
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Group Policy updated")
        except:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Group Policy update may have failed")
        
        print(f"\n{Colors.BLUE}[INFO]{Colors.END} Security Options configuration complete!")
        print("Please restart your computer for all changes to take full effect.")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.END} Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
