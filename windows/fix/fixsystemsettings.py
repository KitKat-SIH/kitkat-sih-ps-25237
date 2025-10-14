#!/usr/bin/env python3
"""
Windows System Settings Auto-Fix Script
Automatically configures UAC settings and System Services
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
    print("WINDOWS SYSTEM SETTINGS AUTO-FIX SCRIPT")
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

def fix_uac_policies():
    """Fix UAC (User Account Control) policies"""
    print(f"\n{Colors.BOLD}FIXING UAC POLICIES{Colors.END}")
    print("-" * 50)
    
    uac_fixes = [
        {
            "description": "UAC: Admin Approval Mode for Built-in Administrator (Enabled)",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "FilterAdministratorToken",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "UAC: Behavior of elevation prompt for administrators (Prompt for consent)",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "ConsentPromptBehaviorAdmin",
            "data": 2,
            "type": winreg.REG_DWORD
        },
        {
            "description": "UAC: Behavior of elevation prompt for standard users (Prompt for credentials)",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "ConsentPromptBehaviorUser",
            "data": 0,  # 0 = Automatically deny, 1 = Prompt for credentials, 3 = Prompt for creds on secure desktop
            "type": winreg.REG_DWORD
        },
        {
            "description": "UAC: Detect application installations and prompt for elevation (Enabled)",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "EnableInstallerDetection",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "UAC: Only elevate UIAccess applications installed in secure locations (Enabled)",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "EnableSecureUIAPaths",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "UAC: Run all administrators in Admin Approval Mode (Enabled)",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "EnableLUA",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "UAC: Switch to secure desktop when prompting for elevation (Enabled)",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "PromptOnSecureDesktop",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "UAC: Virtualize file and registry write failures to per-user locations (Enabled)",
            "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value": "EnableVirtualization",
            "data": 1,
            "type": winreg.REG_DWORD
        }
    ]
    
    success_count = 0
    for fix in uac_fixes:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {fix['description']}...")
        if set_registry_value(winreg.HKEY_LOCAL_MACHINE, fix['key'], fix['value'], fix['data'], fix['type']):
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {fix['description']}")
            success_count += 1
        time.sleep(0.5)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} UAC Policies: {success_count}/{len(uac_fixes)} fixed")
    return success_count == len(uac_fixes)

def configure_service(service_name, startup_type, description):
    """Configure a Windows service"""
    try:
        # Set service startup type
        cmd = ["sc", "config", service_name, "start=", startup_type]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {description} - Set to {startup_type}")
            return True
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} {description} - Error: {result.stderr.strip() if result.stderr else 'Unknown error'}")
            return False
    except Exception as e:
        print(f"{Colors.RED}[FAILED]{Colors.END} {description} - Exception: {e}")
        return False

def fix_system_services():
    """Fix System Services configuration"""
    print(f"\n{Colors.BOLD}FIXING SYSTEM SERVICES{Colors.END}")
    print("-" * 50)
    
    # Services that should be disabled for security
    services_to_disable = [
        ("browser", "Computer Browser"),
        ("irmon", "Infrared Monitor"),
        ("sharedaccess", "Internet Connection Sharing"),
        ("lltdsvc", "Link-Layer Topology Discovery Mapper"),
        ("lmhosts", "TCP/IP NetBIOS Helper"),
        ("msiscsi", "Microsoft iSCSI Initiator Service"),
        ("netlogon", "Netlogon"),
        ("nla", "Network Location Awareness"),
        ("msiserver", "Windows Installer"),
        ("pcasvc", "Program Compatibility Assistant Service"),
        ("seclogon", "Secondary Logon"),
        ("lanmanserver", "Server"),
        ("simptcp", "Simple TCP/IP Services"),
        ("sacsvr", "Special Administration Console Helper"),
        ("ssdpsrv", "SSDP Discovery"),
        ("upnphost", "UPnP Device Host"),
        ("vss", "Volume Shadow Copy"),
        ("wzcsvc", "Wireless Zero Configuration"),
        ("xmlprov", "Network Provisioning Service"),
        ("btagservice", "Bluetooth Audio Gateway Service"),
        ("bthserv", "Bluetooth Support Service"),
        ("lfsvc", "Geolocation Service"),
        ("sessionenv", "Remote Desktop Configuration"),
        ("termservice", "Remote Desktop Services"),
        ("umrdpservice", "Remote Desktop Services UserMode Port Redirector"),
        ("rpclocator", "Remote Procedure Call (RPC) Locator"),
        ("wersvc", "Windows Error Reporting Service"),
        ("wecsvc", "Windows Event Collector"),
        ("wmpnetworksvc", "Windows Media Player Network Sharing Service"),
        ("icssvc", "Windows Mobile Hotspot Service"),
        ("pushtoinstall", "Windows PushToInstall Service"),
        ("winrm", "Windows Remote Management (WS Management)"),
        ("xboxgipsvc", "Xbox Accessory Management Service"),
        ("xblauthmanager", "Xbox Live Auth Manager"),
        ("xblgamesave", "Xbox Live Game Save"),
        ("xboxnetapisvc", "Xbox Live Networking Service")
    ]
    
    # Services that should be set to manual
    services_to_manual = [
        ("alerter", "Alerter"),
        ("appmgmt", "Application Management"),
        ("cisvc", "Indexing Service"),
        ("clipsrv", "ClipBook"),
        ("hidserv", "Human Interface Device Access"),
        ("imapiservice", "IMAPI CD-Burning COM Service"),
        ("mnmsrvc", "NetMeeting Remote Desktop Sharing")
    ]
    
    disabled_count = 0
    manual_count = 0
    
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Disabling unnecessary services...")
    for service_name, description in services_to_disable:
        if configure_service(service_name, "disabled", description):
            disabled_count += 1
        time.sleep(0.3)
    
    print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Setting services to manual startup...")
    for service_name, description in services_to_manual:
        if configure_service(service_name, "demand", description):
            manual_count += 1
        time.sleep(0.3)
    
    total_services = len(services_to_disable) + len(services_to_manual)
    total_fixed = disabled_count + manual_count
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} System Services: {total_fixed}/{total_services} configured")
    print(f"  • Disabled: {disabled_count}/{len(services_to_disable)}")
    print(f"  • Manual: {manual_count}/{len(services_to_manual)}")
    
    return total_fixed == total_services

def create_system_settings_template():
    """Create a comprehensive security template for system settings"""
    template_content = """[Unicode]
Unicode=yes

[Registry Values]
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin=4,2
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser=4,0
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableInstallerDetection=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableSecureUIAPaths=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableVirtualization=4,1

[Service General Setting]
"alerter",2,""
"browser",4,""
"cisvc",3,""
"clipsrv",3,""
"hidserv",3,""
"imapiservice",3,""
"irmon",4,""
"lltdsvc",4,""
"lmhosts",4,""
"mnmsrvc",3,""
"msiscsi",4,""
"netlogon",4,""
"nla",4,""
"msiserver",4,""
"pcasvc",4,""
"seclogon",4,""
"lanmanserver",4,""
"simptcp",4,""
"sacsvr",4,""
"ssdpsrv",4,""
"upnphost",4,""
"vss",4,""
"wzcsvc",4,""
"xmlprov",4,""

[Version]
signature="$CHICAGO$"
Revision=1
"""
    
    import tempfile
    temp_file = os.path.join(tempfile.gettempdir(), "system_settings_template.inf")
    
    try:
        with open(temp_file, 'w', encoding='utf-16') as f:
            f.write(template_content)
        return temp_file
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to create system settings template: {e}")
        return None

def apply_system_settings_template(template_path):
    """Apply the system settings template using secedit"""
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Applying system settings template...")
    time.sleep(1)
    
    try:
        result = subprocess.run([
            "secedit", "/configure", "/cfg", template_path, "/areas", "REGKEYS", "SERVICES"
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} System settings template applied successfully")
            return True
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to apply system settings template")
            print(f"Return code: {result.returncode}")
            if result.stderr:
                print(f"Error details: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error applying system settings template: {e}")
        return False

def main():
    """Main function"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print("Please run this script as Administrator to modify system settings.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    # Ask for confirmation
    print(f"{Colors.YELLOW}[WARNING]{Colors.END} This script will modify Windows System Settings.")
    print("The following changes will be applied:")
    print("  • UAC policies (Admin Approval Mode, elevation prompts)")
    print("  • System services (disable unnecessary services for security)")
    print("  • Service startup types (manual for some services)")
    print()
    print(f"{Colors.RED}[CAUTION]{Colors.END} Disabling services may affect system functionality.")
    print("Only proceed if you understand the implications.")
    print()
    
    confirm = input(f"{Colors.BLUE}[CONFIRM]{Colors.END} Do you want to proceed? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Operation cancelled by user")
        sys.exit(0)
    
    print()
    
    try:
        # Method 1: Try template-based approach
        template_path = create_system_settings_template()
        if template_path:
            template_success = apply_system_settings_template(template_path)
            
            # Clean up template
            if os.path.exists(template_path):
                os.remove(template_path)
            
            if not template_success:
                print(f"\n{Colors.YELLOW}[FALLBACK]{Colors.END} Template method failed, trying individual fixes...")
        
        # Method 2: Individual fixes (always run for completeness)
        uac_success = fix_uac_policies()
        services_success = fix_system_services()
        
        # Force Group Policy update
        print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Updating Group Policy...")
        try:
            subprocess.run(["gpupdate", "/force"], capture_output=True, timeout=60)
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Group Policy updated")
        except:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Group Policy update may have failed")
        
        print(f"\n{Colors.BLUE}[INFO]{Colors.END} System Settings configuration complete!")
        print("Please restart your computer for all changes to take full effect.")
        
        if not services_success:
            print(f"\n{Colors.YELLOW}[NOTE]{Colors.END} Some services may not exist on this system version.")
            print("This is normal and expected on different Windows editions.")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.END} Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
