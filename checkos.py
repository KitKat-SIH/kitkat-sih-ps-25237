import platform
import time
import socket
import subprocess

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'  

def get_os_info():
    os_name = platform.system()
    if os_name == "Windows":
        
        release, version, csd, ptype = platform.win32_ver()
        distro = f"Windows {release or 'Unknown'}"
        os_version = version or platform.version()
    elif os_name == "Darwin":
        # macOS-
        os_version = platform.mac_ver()[0] or "Unknown"
        distro = "macOS"
    else:
        # Linux 
        os_version = platform.version()
        distro = ""
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        distro = line.split("=")[1].strip().strip('"')
                        break
        except FileNotFoundError:
            distro = os_name
    return os_name, distro, os_version

def main():
    os_name, distro, os_version = get_os_info()
    kernel_version = platform.release()
    hostname = socket.gethostname()
    arch = platform.machine()

    print("[+] Initializing program")
    print("------------------------------------")
    print(f"  - Detecting OS...                                           [{Colors.GREEN} DONE {Colors.END}]")
    time.sleep(0.2)
    print(f"  - Checking profiles...                                      [{Colors.GREEN} DONE {Colors.END}]\n")
    time.sleep(0.3)

    print("  ---------------------------------------------------")
    print(f"  Program version:           3.0.9")
    print(f"  Operating system:          {os_name}")
    print(f"  Operating system name:     {distro.split()[0] if distro else os_name}")
    print(f"  Operating system version:  {os_version[1:]}")
    print(f"  Kernel version:            {kernel_version}")
    print(f"  Hardware platform:         {arch}")
    print(f"  Hostname:                  {hostname}")
    print("  ---------------------------------------------------")


if __name__ == "__main__":
    main()
    os_name = platform.system()
    if os_name == "Windows":
        subprocess.run(["python",r"windows\check\accountpolicies.py"])
    elif os_name == "Linux":
        subprocess.run(["python",r"linux/checkvuln.py"])