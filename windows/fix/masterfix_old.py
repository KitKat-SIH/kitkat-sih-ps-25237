#!/usr/bin/env python3
"""
Windows Security Master Auto-Fix Script
Runs all Windows security fixing scripts in sequence
"""

import subprocess
import os
import platform
import ctypes
import sys
import time
from pathlib import Path

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
    print("WINDOWS SECURITY MASTER AUTO-FIX SCRIPT")
    print(f"{Colors.BLUE}=" * 70 + f"{Colors.END}")
    print("This script will run all Windows security fixing scripts")
    print()

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

def run_script(script_path, script_name):
    """Run a fixing script and return success status"""
    print(f"\n{Colors.BOLD}RUNNING {script_name.upper()}{Colors.END}")
    print("=" * 70)
    
    if not os.path.exists(script_path):
        print(f"{Colors.RED}[ERROR]{Colors.END} Script not found: {script_path}")
        return False
    
    try:
        print(f"{Colors.YELLOW}[STARTING]{Colors.END} {script_name}...")
        
        # Run the script
        result = subprocess.run([
            "python", script_path
        ], timeout=600)  # 10 minute timeout per script
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}[COMPLETED]{Colors.END} {script_name} finished successfully")
            return True
        else:
            print(f"{Colors.RED}[FAILED]{Colors.END} {script_name} failed with return code {result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}[TIMEOUT]{Colors.END} {script_name} timed out after 10 minutes")
        return False
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INTERRUPTED]{Colors.END} {script_name} was interrupted by user")
        raise
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} Error running {script_name}: {e}")
        return False

def main():
    """Main function"""
    print_banner()
    check_windows_os()
    
    if not is_admin():
        print(f"{Colors.RED}[ERROR]{Colors.END} Administrator privileges required")
        print("Please run this script as Administrator to modify Windows security settings.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Running with Administrator privileges\n")
    
    # Get the directory where this script is located
    script_dir = Path(__file__).parent
    
    # Define the fixing scripts to run
    fixing_scripts = [
        {
            "path": script_dir / "fixaccountpolicies.py",
            "name": "Account Policies Fixer",
            "description": "Password and account lockout policies"
        },
        {
            "path": script_dir / "fixlocalpolicies.py", 
            "name": "Local Policies Fixer",
            "description": "User Rights Assignments"
        },
        {
            "path": script_dir / "fixsecurityoptions.py",
            "name": "Security Options Fixer", 
            "description": "Accounts, logon, network access, and network security"
        },
        {
            "path": script_dir / "fixsystemsettings.py",
            "name": "System Settings Fixer",
            "description": "UAC policies and system services"
        },
        {
            "path": script_dir / "fixauditpolicies.py",
            "name": "Audit Policies Fixer",
            "description": "Advanced audit policies, SMB v1, and AutoPlay"
        },
        {
            "path": script_dir / "fixdefenderapplication.py",
            "name": "Defender Application Guard Fixer",
            "description": "Microsoft Defender Application Guard policies"
        },
        {
            "path": script_dir / "fixdefenderfirewall.py",
            "name": "Defender Firewall Fixer",
            "description": "Windows Defender Firewall configuration and rules"
        }
    ]
    
    # Display what will be executed
    print(f"{Colors.YELLOW}[INFORMATION]{Colors.END} The following security fixes will be applied:")
    for i, script in enumerate(fixing_scripts, 1):
        status = "✓" if script["path"].exists() else "✗"
        print(f"  {i}. {script['name']} - {script['description']} {status}")
    
    print()
    print(f"{Colors.RED}[WARNING]{Colors.END} This will make significant changes to Windows security settings.")
    print("The process may take 15-30 minutes to complete.")
    print("A system restart will be required after completion.")
    print()
    
    # Ask for confirmation
    confirm = input(f"{Colors.BLUE}[CONFIRM]{Colors.END} Do you want to proceed with all fixes? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[CANCELLED]{Colors.END} Operation cancelled by user")
        sys.exit(0)
    
    print(f"\n{Colors.GREEN}[STARTING]{Colors.END} Beginning Windows security configuration...")
    
    # Track results
    results = {}
    start_time = time.time()
    
    try:
        # Run each script
        for script in fixing_scripts:
            script_start_time = time.time()
            
            if not script["path"].exists():
                print(f"\n{Colors.RED}[SKIPPED]{Colors.END} {script['name']} - Script file not found")
                results[script["name"]] = False
                continue
            
            success = run_script(str(script["path"]), script["name"])
            results[script["name"]] = success
            
            script_duration = time.time() - script_start_time
            print(f"{Colors.BLUE}[TIMING]{Colors.END} {script['name']} took {script_duration:.1f} seconds")
            
            # Small delay between scripts
            time.sleep(2)
        
        # Calculate total time
        total_duration = time.time() - start_time
        
        # Display final results
        print(f"\n{Colors.BOLD}FINAL RESULTS{Colors.END}")
        print("=" * 70)
        
        success_count = 0
        total_count = len(results)
        
        for script_name, success in results.items():
            status = f"{Colors.GREEN}[SUCCESS]{Colors.END}" if success else f"{Colors.RED}[FAILED]{Colors.END}"
            print(f"{status} {script_name}")
            if success:
                success_count += 1
        
        print(f"\n{Colors.BLUE}[SUMMARY]{Colors.END} {success_count}/{total_count} scripts completed successfully")
        print(f"{Colors.BLUE}[TIMING]{Colors.END} Total execution time: {total_duration:.1f} seconds")
        
        if success_count == total_count:
            print(f"\n{Colors.GREEN}[COMPLETE]{Colors.END} All Windows security fixes have been applied successfully!")
        elif success_count > 0:
            print(f"\n{Colors.YELLOW}[PARTIAL]{Colors.END} Some fixes were applied, but {total_count - success_count} scripts failed.")
        else:
            print(f"\n{Colors.RED}[FAILED]{Colors.END} No fixes were applied successfully.")
        
        # Final recommendations
        print(f"\n{Colors.BOLD}NEXT STEPS{Colors.END}")
        print("-" * 70)
        print("1. Restart your computer to ensure all changes take effect")
        print("2. Run the corresponding checker scripts to verify configuration")
        print("3. Test system functionality after restart")
        print("4. Check Windows Event Logs for any issues")
        
        if success_count > 0:
            print(f"\n{Colors.BLUE}[INFO]{Colors.END} Group Policy has been updated automatically.")
            print("Some changes may require a restart to be fully effective.")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CANCELLED]{Colors.END} Operation interrupted by user")
        print("Some fixes may have been partially applied.")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[ERROR]{Colors.END} Unexpected error: {e}")
        sys.exit(1)
    
    print(f"\n{Colors.BLUE}[FINISHED]{Colors.END} Windows Security Master Auto-Fix completed.")
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()