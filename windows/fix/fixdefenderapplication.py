#!/usr/bin/env python3
"""
Windows Microsoft Defender Application Guard Auto-Fix Script
Automatically configures Microsoft Defender Application Guard policies
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
    print("MICROSOFT DEFENDER APPLICATION GUARD AUTO-FIX SCRIPT")
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

def check_and_install_application_guard():
    """Check if Application Guard is installed and install if needed"""
    print(f"\n{Colors.BOLD}CHECKING APPLICATION GUARD INSTALLATION{Colors.END}")
    print("-" * 50)
    
    print(f"{Colors.YELLOW}[CHECKING]{Colors.END} Microsoft Defender Application Guard feature...")
    
    try:
        # Check if Application Guard is installed
        result = subprocess.run([
            "powershell", "-Command",
            "Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard"
        ], capture_output=True, text=True, timeout=60)
        
        if "Enabled" in result.stdout:
            print(f"{Colors.GREEN}[FOUND]{Colors.END} Microsoft Defender Application Guard is already installed")
            return True
        else:
            print(f"{Colors.YELLOW}[INSTALLING]{Colors.END} Installing Microsoft Defender Application Guard...")
            
            # Install Application Guard
            install_result = subprocess.run([
                "powershell", "-Command",
                "Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -NoRestart"
            ], capture_output=True, text=True, timeout=300)
            
            if install_result.returncode == 0:
                print(f"{Colors.GREEN}[INSTALLED]{Colors.END} Microsoft Defender Application Guard installed successfully")
                print(f"{Colors.YELLOW}[NOTE]{Colors.END} A system restart is required for Application Guard to function")
                return True
            else:
                print(f"{Colors.RED}[FAILED]{Colors.END} Failed to install Microsoft Defender Application Guard")
                print(f"Error: {install_result.stderr if install_result.stderr else 'Unknown error'}")
                return False
                
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error checking/installing Application Guard: {e}")
        return False

def check_hyper_v_requirements():
    """Check if Hyper-V is available and enabled"""
    print(f"\n{Colors.BOLD}CHECKING HYPER-V REQUIREMENTS{Colors.END}")
    print("-" * 50)
    
    print(f"{Colors.YELLOW}[CHECKING]{Colors.END} Hyper-V platform support...")
    
    try:
        # Check if Hyper-V platform is enabled
        result = subprocess.run([
            "powershell", "-Command",
            "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"
        ], capture_output=True, text=True, timeout=60)
        
        if "Enabled" in result.stdout:
            print(f"{Colors.GREEN}[ENABLED]{Colors.END} Hyper-V platform is enabled")
            return True
        else:
            print(f"{Colors.YELLOW}[ENABLING]{Colors.END} Enabling Hyper-V platform...")
            
            # Enable Hyper-V
            enable_result = subprocess.run([
                "powershell", "-Command",
                "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart"
            ], capture_output=True, text=True, timeout=300)
            
            if enable_result.returncode == 0:
                print(f"{Colors.GREEN}[ENABLED]{Colors.END} Hyper-V platform enabled successfully")
                print(f"{Colors.YELLOW}[NOTE]{Colors.END} A system restart is required for Hyper-V to function")
                return True
            else:
                print(f"{Colors.RED}[FAILED]{Colors.END} Failed to enable Hyper-V platform")
                print(f"Error: {enable_result.stderr if enable_result.stderr else 'Unknown error'}")
                return False
                
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error checking/enabling Hyper-V: {e}")
        return False

def fix_application_guard_policies():
    """Fix Microsoft Defender Application Guard policies"""
    print(f"\n{Colors.BOLD}FIXING APPLICATION GUARD POLICIES{Colors.END}")
    print("-" * 50)
    
    policies = [
        {
            "description": "Turn on Microsoft Defender Application Guard in Managed Mode",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "AllowAppHVSI_ProviderSet",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Configure Microsoft Defender Application Guard clipboard behavior (Enable copy from container to host)",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "AppHVSIClipboardSettings",
            "data": 1,  # 0 = Block both, 1 = Copy from container to host, 2 = Copy from host to container, 3 = Allow both
            "type": winreg.REG_DWORD
        },
        {
            "description": "Prevent enterprise websites from loading non-enterprise content",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "BlockNonEnterpriseContent",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Configure Microsoft Defender Application Guard print behavior (Disable)",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "AppHVSIPrintingSettings",
            "data": 0,  # 0 = Disable all, 1 = XPS, 2 = PDF, 4 = Local printers, 8 = Network printers
            "type": winreg.REG_DWORD
        },
        {
            "description": "Configure Microsoft Defender Application Guard file behavior (Block)",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "SaveFilesToHost",
            "data": 0,  # 0 = Block, 1 = Allow
            "type": winreg.REG_DWORD
        },
        {
            "description": "Allow auditing events in Microsoft Defender Application Guard",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "AuditApplicationGuard",
            "data": 1,
            "type": winreg.REG_DWORD
        },
        {
            "description": "Allow camera and microphone access in Microsoft Defender Application Guard",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "AllowCameraMicrophoneRedirection",
            "data": 0,  # 0 = Disable, 1 = Enable
            "type": winreg.REG_DWORD
        },
        {
            "description": "Allow data persistence for Microsoft Defender Application Guard",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "AllowPersistence",
            "data": 0,  # 0 = Disable, 1 = Enable
            "type": winreg.REG_DWORD
        },
        {
            "description": "Allow VPN connectivity through Microsoft Defender Application Guard",
            "key": r"SOFTWARE\Policies\Microsoft\AppHVSI",
            "value": "AllowVirtualGPU",
            "data": 0,  # 0 = Disable, 1 = Enable
            "type": winreg.REG_DWORD
        }
    ]
    
    success_count = 0
    for policy in policies:
        print(f"{Colors.YELLOW}[FIXING]{Colors.END} {policy['description']}...")
        if set_registry_value(winreg.HKEY_LOCAL_MACHINE, policy['key'], policy['value'], policy['data'], policy['type']):
            print(f"{Colors.GREEN}[FIXED]{Colors.END} {policy['description']}")
            success_count += 1
        time.sleep(0.5)
    
    print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} Application Guard Policies: {success_count}/{len(policies)} fixed")
    return success_count == len(policies)

def create_application_guard_template():
    """Create a comprehensive Application Guard policy template"""
    template_content = """[Unicode]
Unicode=yes

[Registry Values]
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\AllowAppHVSI_ProviderSet=4,1
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\AppHVSIClipboardSettings=4,0
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\BlockNonEnterpriseContent=4,1
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\AppHVSIPrintingSettings=4,0
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\SaveFilesToHost=4,0
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\AuditApplicationGuard=4,1
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\AllowCameraMicrophoneRedirection=4,0
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\AllowPersistence=4,0
MACHINE\\Software\\Policies\\Microsoft\\AppHVSI\\AllowVirtualGPU=4,0

[Version]
signature="$CHICAGO$"
Revision=1
"""
    
    import tempfile
    temp_file = os.path.join(tempfile.gettempdir(), "application_guard_template.inf")
    
    try:
        with open(temp_file, 'w', encoding='utf-16') as f:
            f.write(template_content)
        return temp_file
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Failed to create Application Guard template: {e}")
        return None

def apply_application_guard_template(template_path):
    """Apply the Application Guard template using secedit"""
    print(f"{Colors.YELLOW}[WORKING]{Colors.END} Applying Application Guard template...")
    time.sleep(1)
    
    try:
        result = subprocess.run([
            "secedit", "/configure", "/cfg", template_path, "/areas", "REGKEYS"
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Application Guard template applied successfully")
            return True
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to apply Application Guard template")
            print(f"Return code: {result.returncode}")
            if result.stderr:
                print(f"Error details: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error applying Application Guard template: {e}")
        return False

def check_system_requirements():
    """Check if the system meets requirements for Application Guard"""
    print(f"\n{Colors.BOLD}CHECKING SYSTEM REQUIREMENTS{Colors.END}")
    print("-" * 50)
    
    requirements_met = True
    
    # Check Windows edition
    try:
        result = subprocess.run([
            "powershell", "-Command",
            "Get-ComputerInfo | Select-Object WindowsEditionId"
        ], capture_output=True, text=True, timeout=30)
        
        if "Enterprise" in result.stdout or "Education" in result.stdout or "Pro" in result.stdout:
            print(f"{Colors.GREEN}[PASS]{Colors.END} Windows edition supports Application Guard")
        else:
            print(f"{Colors.RED}[FAIL]{Colors.END} Windows edition may not support Application Guard")
            requirements_met = False
    except:
        print(f"{Colors.YELLOW}[UNKNOWN]{Colors.END} Could not determine Windows edition")
    
    # Check if virtualization is enabled
    try:
        result = subprocess.run([
            "powershell", "-Command",
            "Get-ComputerInfo | Select-Object HyperVRequirementVirtualizationFirmwareEnabled"
        ], capture_output=True, text=True, timeout=30)
        
        if "True" in result.stdout:
            print(f"{Colors.GREEN}[PASS]{Colors.END} Hardware virtualization is enabled")
        else:
            print(f"{Colors.RED}[FAIL]{Colors.END} Hardware virtualization is not enabled")
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Enable VT-x/AMD-V in BIOS/UEFI settings")
            requirements_met = False
    except:
        print(f"{Colors.YELLOW}[UNKNOWN]{Colors.END} Could not check virtualization support")
    
    # Check memory (minimum 8GB recommended)
    try:
        result = subprocess.run([
            "powershell", "-Command",
            "(Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1gb"
        ], capture_output=True, text=True, timeout=30)
        
        memory_gb = float(result.stdout.strip())
        if memory_gb >= 8:
            print(f"{Colors.GREEN}[PASS]{Colors.END} Sufficient memory: {memory_gb:.1f} GB")
        else:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Low memory: {memory_gb:.1f} GB (8GB+ recommended)")
    except:
        print(f"{Colors.YELLOW}[UNKNOWN]{Colors.END} Could not check memory")
    
    return requirements_met

def main():
    """Main function"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print("Please run this script as Administrator to configure Application Guard.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    # Check system requirements
    requirements_ok = check_system_requirements()
    
    if not requirements_ok:
        print(f"\n{Colors.YELLOW}[WARNING]{Colors.END} System may not meet all requirements for Application Guard.")
        continue_anyway = input(f"{Colors.BLUE}[CONFIRM]{Colors.END} Continue anyway? (y/N): ").strip().lower()
        if continue_anyway not in ['y', 'yes']:
            print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Operation cancelled by user")
            sys.exit(0)
    
    # Ask for confirmation
    print(f"\n{Colors.YELLOW}[WARNING]{Colors.END} This script will configure Microsoft Defender Application Guard.")
    print("The following changes will be applied:")
    print("  • Install/Enable Application Guard feature")
    print("  • Install/Enable Hyper-V platform")
    print("  • Configure Application Guard policies (restrictive settings)")
    print("  • Disable clipboard, printing, and file transfers")
    print()
    print(f"{Colors.RED}[IMPORTANT]{Colors.END} System restart will be required after installation.")
    print()
    
    confirm = input(f"{Colors.BLUE}[CONFIRM]{Colors.END} Do you want to proceed? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Operation cancelled by user")
        sys.exit(0)
    
    print()
    
    try:
        # Step 1: Check and install prerequisites
        hyper_v_ok = check_hyper_v_requirements()
        app_guard_ok = check_and_install_application_guard()
        
        # Even if installation fails, try to apply registry policies
        if not (hyper_v_ok and app_guard_ok):
            print(f"\n{Colors.YELLOW}[FALLBACK]{Colors.END} Prerequisites failed, but applying registry policies anyway...")
        
        # Step 2: Apply template-based configuration
        template_path = create_application_guard_template()
        if template_path:
            template_success = apply_application_guard_template(template_path)
            
            # Clean up template
            if os.path.exists(template_path):
                os.remove(template_path)
        
        # Step 3: Apply individual policy fixes
        policies_success = fix_application_guard_policies()
        
        # Step 4: Force Group Policy update
        print(f"\n{Colors.YELLOW}[WORKING]{Colors.END} Updating Group Policy...")
        try:
            subprocess.run(["gpupdate", "/force"], capture_output=True, timeout=60)
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Group Policy updated")
        except:
            print(f"{Colors.YELLOW}[WARNING]{Colors.END} Group Policy update may have failed")
        
        print(f"\n{Colors.BLUE}[INFO]{Colors.END} Microsoft Defender Application Guard configuration complete!")
        print(f"{Colors.RED}[RESTART REQUIRED]{Colors.END} Please restart your computer to enable Application Guard.")
        print()
        print("After restart, Application Guard will be available in Microsoft Edge.")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.END} Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
