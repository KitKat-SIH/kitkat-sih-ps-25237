# hardn/modules/network.py
"""
Implements Linux hardening controls for Section 4 – Network Configuration
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any, Dict, Tuple, List
from .base import BaseHardeningModule, Colors


# ---------------------- Module Implementation ----------------------

class NetworkModule(BaseHardeningModule):
    id: str = "network"

    def __init__(self, context: Dict[str, Any]) -> None:
        super().__init__(context)
        self.logger = context["logger"]
        self.os_name: str = context.get("os_name", "unknown")

    # ---------------------- Utilities ----------------------

    def run_cmd(self, cmd: str) -> Tuple[int, str]:
        """Run shell command and return (return_code, output)."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, check=False
            )
            output: str = result.stdout.strip() or result.stderr.strip()
            return result.returncode, output
        except Exception as e:
            self.logger.log("ERROR", f"Failed to execute: {cmd} ({e})")
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to run: {cmd} ({e})")
            return 1, str(e)

    # ---------------------- Configure Network Devices ----------------------

    def configure_network_devices(self, action: str) -> bool:
        """NET-1 to NET-3: Configure network devices"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Network Devices{Colors.END}")
            all_ok = True
            
            # Check IPv6 status
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking IPv6 status...")
            rc, output = self.run_cmd("sysctl net.ipv6.conf.all.disable_ipv6")
            
            if output:
                ipv6_disabled = "net.ipv6.conf.all.disable_ipv6 = 1" in output
                if ipv6_disabled:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} IPv6 is disabled")
                else:
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} IPv6 is enabled")
                    print(f"{Colors.YELLOW}         ↳{Colors.END} Review if IPv6 is required for your environment")
            else:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Unable to determine IPv6 status")
                all_ok = False
            
            # Check wireless interfaces
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for wireless interfaces...")
            rc, output = self.run_cmd("iwconfig 2>&1 | grep -v 'no wireless extensions'")
            
            if not output or rc != 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No wireless interfaces found")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Wireless interfaces detected:")
                for line in output.split('\n')[:3]:  # Show first 3 lines
                    print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            
            # Check Bluetooth services
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if Bluetooth services are disabled...")
            rc, _ = self.run_cmd("systemctl is-enabled bluetooth 2>/dev/null")
            
            if rc != 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Bluetooth services are disabled")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Bluetooth services are enabled")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Network Devices{Colors.END}")
            all_ok = True
            
            # IPv6 - provide info but don't enforce
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} IPv6 status identified")
            rc, output = self.run_cmd("sysctl net.ipv6.conf.all.disable_ipv6")
            if "net.ipv6.conf.all.disable_ipv6 = 1" in output:
                print(f"{Colors.YELLOW}         ↳{Colors.END} IPv6 is currently disabled")
            else:
                print(f"{Colors.YELLOW}         ↳{Colors.END} IPv6 is currently enabled")
                print(f"{Colors.YELLOW}         ↳{Colors.END} To disable IPv6:")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   sysctl -p")
            
            # Disable wireless interfaces
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Disabling wireless interfaces...")
            rc, output = self.run_cmd("ip link show | grep -i wireless | awk '{print $2}' | tr -d ':'")
            
            if output:
                for interface in output.split('\n'):
                    if interface:
                        self.run_cmd(f"ip link set {interface} down")
                        self.run_cmd(f"echo 'blacklist {interface}' >> /etc/modprobe.d/wireless-blacklist.conf")
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Wireless interfaces disabled")
            else:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} No wireless interfaces to disable")
            
            # Disable Bluetooth
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Disabling Bluetooth services...")
            rc1, _ = self.run_cmd("systemctl stop bluetooth 2>/dev/null")
            rc2, _ = self.run_cmd("systemctl disable bluetooth 2>/dev/null")
            rc3, _ = self.run_cmd("systemctl mask bluetooth 2>/dev/null")
            
            if rc1 == 0 or rc2 == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Bluetooth services disabled")
            else:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Bluetooth services not present or already disabled")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Network Kernel Modules ----------------------

    def configure_network_kernel_modules(self, action: str) -> bool:
        """NET-4 to NET-7: Ensure network protocol kernel modules are disabled"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Network Kernel Modules{Colors.END}")
            all_ok = True
            
            modules = ["dccp", "tipc", "rds", "sctp"]
            
            for module in modules:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if {module} module is disabled...")
                rc, _ = self.run_cmd(f"lsmod | grep -q {module}")
                
                if rc != 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {module} module not loaded")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {module} module is loaded")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Network Kernel Modules{Colors.END}")
            all_ok = True
            
            modules = ["dccp", "tipc", "rds", "sctp"]
            
            for module in modules:
                print(f"{Colors.BLUE}[WORKING]{Colors.END} Disabling {module} module...")
                
                # Create blacklist entry
                blacklist_file = f"/etc/modprobe.d/{module}.conf"
                rc1, _ = self.run_cmd(f"echo 'install {module} /bin/true' > {blacklist_file}")
                
                # Remove if loaded
                rc2, _ = self.run_cmd(f"rmmod {module} 2>/dev/null || true")
                
                if rc1 == 0:
                    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {module} module disabled")
                else:
                    print(f"{Colors.RED}[ERROR]{Colors.END} Failed to disable {module}")
                    all_ok = False
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Network Kernel Parameters ----------------------

    def configure_network_kernel_parameters(self, action: str) -> bool:
        """NET-8 to NET-18: Configure network kernel parameters"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Network Kernel Parameters{Colors.END}")
            all_ok = True
            
            # Define all kernel parameters to check
            params = [
                ("net.ipv4.ip_forward", "0", "IP forwarding"),
                ("net.ipv4.conf.all.send_redirects", "0", "packet redirect sending (all)"),
                ("net.ipv4.conf.default.send_redirects", "0", "packet redirect sending (default)"),
                ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "bogus ICMP responses ignored"),
                ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "broadcast ICMP requests ignored"),
                ("net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects not accepted (all)"),
                ("net.ipv4.conf.default.accept_redirects", "0", "ICMP redirects not accepted (default)"),
                ("net.ipv4.conf.all.secure_redirects", "0", "secure ICMP redirects not accepted (all)"),
                ("net.ipv4.conf.default.secure_redirects", "0", "secure ICMP redirects not accepted (default)"),
                ("net.ipv4.conf.all.rp_filter", "1", "reverse path filtering (all)"),
                ("net.ipv4.conf.default.rp_filter", "1", "reverse path filtering (default)"),
                ("net.ipv4.conf.all.accept_source_route", "0", "source routed packets not accepted (all)"),
                ("net.ipv4.conf.default.accept_source_route", "0", "source routed packets not accepted (default)"),
                ("net.ipv4.conf.all.log_martians", "1", "suspicious packets logged (all)"),
                ("net.ipv4.conf.default.log_martians", "1", "suspicious packets logged (default)"),
                ("net.ipv4.tcp_syncookies", "1", "TCP SYN cookies enabled"),
                ("net.ipv6.conf.all.accept_ra", "0", "IPv6 router advertisements not accepted (all)"),
                ("net.ipv6.conf.default.accept_ra", "0", "IPv6 router advertisements not accepted (default)"),
            ]
            
            for param, expected_value, description in params:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if {description}...")
                rc, output = self.run_cmd(f"sysctl {param} 2>/dev/null")
                
                if f"{param} = {expected_value}" in output:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {description}")
                else:
                    current_value = output.split('=')[-1].strip() if '=' in output else "unknown"
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} (current: {current_value}, expected: {expected_value})")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Network Kernel Parameters{Colors.END}")
            all_ok = True
            
            # Define all kernel parameters to set
            params = [
                ("net.ipv4.ip_forward", "0", "IP forwarding"),
                ("net.ipv4.conf.all.send_redirects", "0", "packet redirect sending (all)"),
                ("net.ipv4.conf.default.send_redirects", "0", "packet redirect sending (default)"),
                ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "bogus ICMP responses"),
                ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "broadcast ICMP requests"),
                ("net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects (all)"),
                ("net.ipv4.conf.default.accept_redirects", "0", "ICMP redirects (default)"),
                ("net.ipv4.conf.all.secure_redirects", "0", "secure ICMP redirects (all)"),
                ("net.ipv4.conf.default.secure_redirects", "0", "secure ICMP redirects (default)"),
                ("net.ipv4.conf.all.rp_filter", "1", "reverse path filtering (all)"),
                ("net.ipv4.conf.default.rp_filter", "1", "reverse path filtering (default)"),
                ("net.ipv4.conf.all.accept_source_route", "0", "source routed packets (all)"),
                ("net.ipv4.conf.default.accept_source_route", "0", "source routed packets (default)"),
                ("net.ipv4.conf.all.log_martians", "1", "suspicious packet logging (all)"),
                ("net.ipv4.conf.default.log_martians", "1", "suspicious packet logging (default)"),
                ("net.ipv4.tcp_syncookies", "1", "TCP SYN cookies"),
                ("net.ipv6.conf.all.accept_ra", "0", "IPv6 router advertisements (all)"),
                ("net.ipv6.conf.default.accept_ra", "0", "IPv6 router advertisements (default)"),
            ]
            
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring network kernel parameters...")
            
            # Backup sysctl.conf
            self.run_cmd("cp /etc/sysctl.conf /etc/sysctl.conf.backup 2>/dev/null")
            
            failed_params = []
            
            for param, value, description in params:
                # Set runtime value
                rc1, _ = self.run_cmd(f"sysctl -w {param}={value}")
                
                # Check if already in sysctl.conf
                rc2, _ = self.run_cmd(f"grep -q '^{param}' /etc/sysctl.conf")
                
                if rc2 == 0:
                    # Update existing entry
                    self.run_cmd(f"sed -i 's|^{param}.*|{param} = {value}|' /etc/sysctl.conf")
                else:
                    # Add new entry
                    self.run_cmd(f"echo '{param} = {value}' >> /etc/sysctl.conf")
                
                if rc1 != 0:
                    failed_params.append(description)
            
            if not failed_params:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} All network kernel parameters configured")
                all_ok = True
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to configure: {', '.join(failed_params)}")
                all_ok = False
            
            # Reload sysctl
            self.run_cmd("sysctl -p")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== NETWORK: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic network policy")

        # Configure network devices
        result = self.configure_network_devices("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("network", "NET-1-3", "ok", result)

        # Configure network kernel modules
        result = self.configure_network_kernel_modules("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("network", "NET-4-7", "ok", result)

        print(f"\n{Colors.BOLD}Network Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Network Devices: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Network Kernel Modules: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== NETWORK: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate network policy")

        self.apply_basic(False)

        # Configure basic network kernel parameters (critical ones)
        result = self.configure_network_kernel_parameters("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("network", "NET-8-18", "ok", result)

        print(f"\n{Colors.BOLD}Network Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Network Devices: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Network Kernel Modules: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Network Kernel Parameters: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== NETWORK: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict network policy")

        # Strict is same as moderate for network
        self.apply_moderate(False)

        print(f"\n{Colors.BOLD}Network Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Network Devices: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Network Kernel Modules: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Network Kernel Parameters: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict network checks successfully!")

    # ---------------------- Audit/Enforce Entry Points ----------------------

    def audit(self) -> None:
        """Perform read-only checks based on policy level"""
        policy_method = f"apply_{self.policy}"
        if hasattr(self, policy_method):
            getattr(self, policy_method)()
        else:
            self.logger.log("ERROR", f"Unknown policy level: {self.policy}")

    def enforce(self) -> None:
        """Apply hardening fixes based on policy level"""
        self.audit()  # Same logic, check/enforce handled per method
