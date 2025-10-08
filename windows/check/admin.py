#!/usr/bin/env python3
import sys
import pyuac
import subprocess



class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'  

@pyuac.main_requires_admin
def admin():
    print(f"Admin privelage   [{Colors.GREEN} YES {Colors.END}]\n")


