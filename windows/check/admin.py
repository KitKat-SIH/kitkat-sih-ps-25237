#!/usr/bin/env python3
"""
Administrator privilege helper
Provides utility functions for checking and requesting admin privileges
"""

import ctypes
import sys
import subprocess
import os

def admin():
    """Request administrator privileges if not already running as admin"""
    if is_user_admin():
        print("Already running with administrator privileges.")
        return True
    else:
        print("Administrator privileges required. Requesting elevation...")
        return run_as_admin()

def is_user_admin():
    """Check if the current user has administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Attempt to restart the script with administrator privileges"""
    try:
        if sys.argv[-1] != 'asadmin':
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:] + ['asadmin'])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            return True
        else:
            return False
    except:
        print("Failed to request administrator privileges.")
        return False

if __name__ == "__main__":
    if admin():
        print("Administrator privileges confirmed.")
    else:
        print("Failed to obtain administrator privileges.")
        input("Press Enter to exit...")
        sys.exit(1)