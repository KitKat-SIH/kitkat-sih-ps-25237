import subprocess
import os
import re
import platform

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'  

import subprocess
import os
import re
import ctypes

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_local_security_policy():
    # Check for admin privileges first
    if not is_admin():
        print("Error: This script requires Administrator privileges.")
        print("Please run as Administrator to export security policies.")
        return
    cwd=os.getcwd()
    temp_path = f"{cwd}\\accountpolicies.inf"
    os.makedirs(os.path.dirname(temp_path), exist_ok=True)

    # Export current security policy
    print("Exporting security policy...")
    result = subprocess.run(["secedit", "/export", "/cfg", temp_path], 
                          capture_output=True, text=True)
    
    # Check if the command was successful
    if result.returncode != 0:
        print(f"Error: secedit command failed with return code {result.returncode}")
        print(f"Error output: {result.stderr}")
        print("Note: This command requires Administrator privileges.")
        return
    
    # Check if the file was actually created
    if not os.path.exists(temp_path):
        print(f"Error: Policy file was not created at {temp_path}")
        print("Please run this script as Administrator.")
        return

    # Read file
    with open(temp_path, "r") as f:
        data = f.read()

    # Parse relevant settings
    checks = {
        "PasswordHistorySize": ("Enforce password history", 24, int),
        "MaximumPasswordAge": ("Maximum password age (days)", 90, int),
        "MinimumPasswordAge": ("Minimum password age (days)", 1, int),
        "MinimumPasswordLength": ("Minimum password length", 12, int),
        "PasswordComplexity": ("Password must meet complexity requirements", 1, int),
        "ClearTextPassword": ("Store passwords using reversible encryption", 0, int),
    }

    print("\nPassword Policy Compliance Report\n" + "-"*50)
    for key, (desc, expected, conv) in checks.items():
        match = re.search(rf"^{key}\s*=\s*(\S+)", data, re.MULTILINE)
        if not match:
            print(f"[!] {desc}: Not found in policy export")
            continue
        value = conv(match.group(1))
        compliant = (
            value >= expected if key in ["PasswordHistorySize", "MinimumPasswordLength"]
            else value == expected
        )
        status = f"[{Colors.GREEN} SAFE {Colors.END}]" if compliant else "[{Colors.RED} UNSAFE {Colors.END}]"
        print(f"{desc:<55} : {value} ({status})")

    # Clean up - only remove if file exists
    if os.path.exists(temp_path):
        os.remove(temp_path)

if __name__ == "__main__":
    if platform.system == "Windows":
        get_local_security_policy()
