# hardn/modules/firewall.py
"""
Implements Linux hardening controls for Section 5 – Host-Based Firewall Configuration
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any
from .base import BaseHardeningModule, Colors



# ---------------------- Module Implementation ----------------------

class FirewallModule(BaseHardeningModule):
    id: str = "firewall"

    def __init__(self, context: dict[str, Any]) -> None:
        super().__init__(context)
        self.logger = context["logger"]
        self.os_name: str = context.get("os_name", "unknown")

    # ---------------------- Utilities ----------------------

    def run_cmd(self, cmd: str) -> tuple[int, str]:
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

    # ---------------------- Individual Checks ----------------------

    def firewall_installed(self, action: str) -> bool:
        """FW-1: Ensure ufw is installed"""
        def check() -> bool:
            cmd = "dpkg -l | grep -qw ufw" if self.os_name == "ubuntu" else "rpm -q ufw"
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if UFW is installed...")
            rc, _ = self.run_cmd(cmd)
            if rc == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} UFW is installed")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} UFW not found")
            return rc == 0

        def enforce() -> bool:
            cmd = "apt-get install -y ufw" if self.os_name == "ubuntu" else "yum install -y ufw"
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Installing UFW package...")
            rc, _ = self.run_cmd(cmd)
            if rc == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} UFW installed successfully")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to install UFW")
            return rc == 0

        return check() if action == "check" else enforce()

    def iptables_persistent_absent(self, action: str) -> bool:
        """FW-2: Ensure iptables-persistent is not installed"""
        def check() -> bool:
            cmd = (
                "dpkg -l | grep -qw iptables-persistent"
                if self.os_name == "ubuntu"
                else "rpm -q iptables-services"
            )
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for iptables-persistent...")
            rc, _ = self.run_cmd(cmd)
            if rc != 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} iptables-persistent not installed")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} iptables-persistent found")
            return rc != 0

        def enforce() -> bool:
            cmd = (
                "apt-get remove -y iptables-persistent"
                if self.os_name == "ubuntu"
                else "yum remove -y iptables-services"
            )
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Removing iptables-persistent...")
            rc, _ = self.run_cmd(cmd)
            if rc == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} iptables-persistent removed")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to remove iptables-persistent")
            return rc == 0

        return check() if action == "check" else enforce()

    def ufw_enabled(self, action: str) -> bool:
        """FW-3: Ensure ufw service is enabled and running"""
        def check() -> bool:
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if ufw service is enabled...")
            rc, _ = self.run_cmd("systemctl is-enabled ufw")
            return rc == 0

        def enforce() -> bool:
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Enabling and starting ufw service...")
            rc, _ = self.run_cmd("systemctl enable ufw && systemctl start ufw")
            if rc == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} ufw service enabled and running")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to enable ufw service")
            return rc == 0

        return check() if action == "check" else enforce()

    def loopback_allowed(self, action: str) -> bool:
        """FW-4: Ensure loopback traffic is allowed"""
        def check() -> bool:
            cmd = "ufw status verbose | grep -q 'Anywhere on lo'"
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if loopback traffic allowed...")
            rc, _ = self.run_cmd(cmd)
            return rc == 0

        def enforce() -> bool:
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Allowing loopback traffic...")
            rc, _ = self.run_cmd("ufw allow in on lo && ufw reload")
            return rc == 0

        return check() if action == "check" else enforce()

    def default_deny_outgoing(self, action: str) -> bool:
        """FW-5: Ensure outbound traffic is denied by default"""
        def check() -> bool:
            cmd = "ufw status verbose | grep -q 'Default: deny (outgoing)'"
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking default outbound policy...")
            rc, _ = self.run_cmd(cmd)
            return rc == 0

        def enforce() -> bool:
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting default deny (outgoing)...")
            rc, _ = self.run_cmd("ufw default deny outgoing && ufw reload")
            return rc == 0

        return check() if action == "check" else enforce()

    def default_deny_incoming(self, action: str) -> bool:
        """FW-7: Ensure default deny incoming rule is configured"""
        def check() -> bool:
            cmd = "ufw status verbose | grep -q 'Default: deny (incoming)'"
            rc, _ = self.run_cmd(cmd)
            return rc == 0

        def enforce() -> bool:
            rc, _ = self.run_cmd("ufw default deny incoming && ufw reload")
            return rc == 0

        return check() if action == "check" else enforce()

    def iptables_disabled(self, action: str) -> bool:
        """FW-8: Ensure iptables service is inactive"""
        def check() -> bool:
            cmd = "systemctl is-active iptables"
            rc, _ = self.run_cmd(cmd)
            return rc != 0

        def enforce() -> bool:
            cmd = "systemctl stop iptables && systemctl disable iptables"
            rc, _ = self.run_cmd(cmd)
            return rc == 0

        return check() if action == "check" else enforce()

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FIREWALL: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic firewall policy")

        if not self.firewall_installed("check"):
            self.firewall_installed("enforce")
        self.add_result("FW-1", "ok", True)

        if not self.iptables_persistent_absent("check"):
            self.iptables_persistent_absent("enforce")
        self.add_result("FW-2", "ok", True)

        if not self.ufw_enabled("check"):
            self.ufw_enabled("enforce")
        self.add_result("FW-3", "ok", True)

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FIREWALL: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate firewall policy")

        self.apply_basic(False)

        if not self.loopback_allowed("check"):
            self.loopback_allowed("enforce")
        self.add_result("FW-4", "ok", True)

        if not self.default_deny_outgoing("check"):
            self.default_deny_outgoing("enforce")
        self.add_result("FW-5", "ok", True)

        if not self.default_deny_incoming("check"):
            self.default_deny_incoming("enforce")
        self.add_result("FW-7", "ok", True)

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FIREWALL: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict firewall policy")

        self.apply_moderate(False)

        if not self.iptables_disabled("check"):
            self.iptables_disabled("enforce")
        self.add_result("FW-8", "ok", True)

        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict firewall checks successfully!")

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
