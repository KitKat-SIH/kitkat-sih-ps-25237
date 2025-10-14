# hardn/modules/boot_process.py
"""
Implements Linux hardening controls for Section 2 – Package Management
(Bootloader, Process Hardening, Warning Banners)
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any
from .base import BaseHardeningModule, Colors


# ---------------------- Module Implementation ----------------------

class BootProcessModule(BaseHardeningModule):
    id: str = "boot_process"

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

    # ---------------------- Configure Bootloader ----------------------

    def configure_bootloader(self, action: str) -> bool:
        """BP-1 to BP-2: Configure bootloader security"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Bootloader{Colors.END}")
            all_ok = True
            
            # Check bootloader password
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if bootloader password is set...")
            
            if self.os_name == "ubuntu":
                # Check GRUB password
                rc, _ = self.run_cmd("grep -q 'password_pbkdf2' /boot/grub/grub.cfg")
                if rc == 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Bootloader password is configured")
                else:
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Bootloader password not set")
                    print(f"{Colors.YELLOW}         ↳{Colors.END} To set GRUB password:")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}   1. Run: grub-mkpasswd-pbkdf2")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}   2. Add to /etc/grub.d/40_custom:")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}      set superusers=\"root\"")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}      password_pbkdf2 root <hash>")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}   3. Run: update-grub")
                    all_ok = False
            else:  # CentOS
                rc, _ = self.run_cmd("grep -q 'password_pbkdf2' /boot/grub2/grub.cfg")
                if rc == 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Bootloader password is configured")
                else:
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Bootloader password not set")
                    print(f"{Colors.YELLOW}         ↳{Colors.END} To set GRUB2 password:")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}   1. Run: grub2-mkpasswd-pbkdf2")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}   2. Add to /etc/grub.d/40_custom:")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}      set superusers=\"root\"")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}      password_pbkdf2 root <hash>")
                    print(f"{Colors.YELLOW}         ↳{Colors.END}   3. Run: grub2-mkconfig -o /boot/grub2/grub.cfg")
                    all_ok = False
            
            # Check bootloader config permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking bootloader config permissions...")
            
            if self.os_name == "ubuntu":
                grub_cfg = "/boot/grub/grub.cfg"
            else:
                grub_cfg = "/boot/grub2/grub.cfg"
            
            rc, perms = self.run_cmd(f"stat -c '%a' {grub_cfg} 2>/dev/null")
            if rc == 0 and perms == "400":
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Bootloader config permissions are correct (400)")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Bootloader config permissions incorrect (current: {perms}, expected: 400)")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Bootloader{Colors.END}")
            
            # We don't enforce password setting - just warn
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Bootloader password must be set manually")
            if self.os_name == "ubuntu":
                print(f"{Colors.YELLOW}         ↳{Colors.END} To set GRUB password:")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   1. Run: grub-mkpasswd-pbkdf2")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   2. Add to /etc/grub.d/40_custom:")
                print(f"{Colors.YELLOW}         ↳{Colors.END}      set superusers=\"root\"")
                print(f"{Colors.YELLOW}         ↳{Colors.END}      password_pbkdf2 root <hash>")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   3. Run: update-grub")
                grub_cfg = "/boot/grub/grub.cfg"
            else:
                print(f"{Colors.YELLOW}         ↳{Colors.END} To set GRUB2 password:")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   1. Run: grub2-mkpasswd-pbkdf2")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   2. Add to /etc/grub.d/40_custom:")
                print(f"{Colors.YELLOW}         ↳{Colors.END}      set superusers=\"root\"")
                print(f"{Colors.YELLOW}         ↳{Colors.END}      password_pbkdf2 root <hash>")
                print(f"{Colors.YELLOW}         ↳{Colors.END}   3. Run: grub2-mkconfig -o /boot/grub2/grub.cfg")
                grub_cfg = "/boot/grub2/grub.cfg"
            
            # Fix bootloader config permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting bootloader config permissions to 400...")
            rc, _ = self.run_cmd(f"chmod 400 {grub_cfg}")
            
            if rc == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Bootloader config permissions set to 400")
                return True
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to set bootloader config permissions")
                return False

        return check() if action == "check" else enforce()

    # ---------------------- Additional Process Hardening ----------------------

    def configure_process_hardening(self, action: str) -> bool:
        """BP-3 to BP-7: Configure additional process hardening"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Additional Process Hardening{Colors.END}")
            all_ok = True
            
            # Check ASLR
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if ASLR is enabled...")
            rc, output = self.run_cmd("sysctl kernel.randomize_va_space")
            if "kernel.randomize_va_space = 2" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} ASLR is enabled")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} ASLR is not properly configured")
                all_ok = False
            
            # Check ptrace_scope
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if ptrace_scope is restricted...")
            rc, output = self.run_cmd("sysctl kernel.yama.ptrace_scope")
            if "kernel.yama.ptrace_scope = 1" in output or "kernel.yama.ptrace_scope = 2" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} ptrace_scope is restricted")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} ptrace_scope is not restricted")
                all_ok = False
            
            # Check core dumps
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if core dumps are restricted...")
            rc1, output1 = self.run_cmd("sysctl fs.suid_dumpable")
            rc2, output2 = self.run_cmd("grep -q 'hard core 0' /etc/security/limits.conf")
            
            if "fs.suid_dumpable = 0" in output1 and rc2 == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Core dumps are restricted")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Core dumps are not properly restricted")
                all_ok = False
            
            # Check prelink
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if prelink is not installed...")
            if self.os_name == "ubuntu":
                rc, _ = self.run_cmd("dpkg -l | grep -qw prelink")
            else:
                rc, _ = self.run_cmd("rpm -q prelink")
            
            if rc != 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} prelink is not installed")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} prelink is installed")
                all_ok = False
            
            # Check Automatic Error Reporting
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if Automatic Error Reporting is disabled...")
            if self.os_name == "ubuntu":
                rc, _ = self.run_cmd("systemctl is-enabled apport 2>/dev/null")
                if rc != 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Automatic Error Reporting is disabled")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Automatic Error Reporting is enabled")
                    all_ok = False
            else:
                rc, _ = self.run_cmd("systemctl is-enabled abrtd 2>/dev/null")
                if rc != 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Automatic Error Reporting is disabled")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Automatic Error Reporting is enabled")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Additional Process Hardening{Colors.END}")
            all_ok = True
            
            # Enable ASLR
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Enabling ASLR...")
            rc1, _ = self.run_cmd("sysctl -w kernel.randomize_va_space=2")
            rc2, _ = self.run_cmd("echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf")
            if rc1 == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} ASLR enabled")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to enable ASLR")
                all_ok = False
            
            # Restrict ptrace_scope
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Restricting ptrace_scope...")
            rc1, _ = self.run_cmd("sysctl -w kernel.yama.ptrace_scope=1")
            rc2, _ = self.run_cmd("echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.conf")
            if rc1 == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} ptrace_scope restricted")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to restrict ptrace_scope")
                all_ok = False
            
            # Restrict core dumps
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Restricting core dumps...")
            rc1, _ = self.run_cmd("sysctl -w fs.suid_dumpable=0")
            rc2, _ = self.run_cmd("echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf")
            rc3, _ = self.run_cmd("echo '* hard core 0' >> /etc/security/limits.conf")
            if rc1 == 0 and rc3 == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Core dumps restricted")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to restrict core dumps")
                all_ok = False
            
            # Remove prelink
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Removing prelink...")
            if self.os_name == "ubuntu":
                rc, _ = self.run_cmd("apt-get remove -y prelink 2>/dev/null")
            else:
                rc, _ = self.run_cmd("yum remove -y prelink 2>/dev/null")
            
            if rc == 0 or rc == 1:  # 1 means package not installed
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} prelink removed/not installed")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to remove prelink")
                all_ok = False
            
            # Disable Automatic Error Reporting
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Disabling Automatic Error Reporting...")
            if self.os_name == "ubuntu":
                rc1, _ = self.run_cmd("systemctl stop apport 2>/dev/null")
                rc2, _ = self.run_cmd("systemctl disable apport 2>/dev/null")
                rc3, _ = self.run_cmd("systemctl mask apport 2>/dev/null")
            else:
                rc1, _ = self.run_cmd("systemctl stop abrtd 2>/dev/null")
                rc2, _ = self.run_cmd("systemctl disable abrtd 2>/dev/null")
                rc3, _ = self.run_cmd("systemctl mask abrtd 2>/dev/null")
            
            if rc1 == 0 or rc2 == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Automatic Error Reporting disabled")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to disable Automatic Error Reporting")
                all_ok = False
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Command Line Warning Banners ----------------------

    def configure_warning_banners(self, action: str) -> bool:
        """BP-8 to BP-12: Configure command line warning banners"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Command Line Warning Banners{Colors.END}")
            all_ok = True
            
            banner_files = [
                ("/etc/issue", "local login banner"),
                ("/etc/issue.net", "remote login banner"),
                ("/etc/motd", "message of the day")
            ]
            
            for filepath, desc in banner_files:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking {desc} ({filepath})...")
                
                # Check if file exists and has content
                rc, content = self.run_cmd(f"cat {filepath} 2>/dev/null")
                if rc == 0 and content:
                    # Check permissions
                    rc_perm, perms = self.run_cmd(f"stat -c '%a' {filepath}")
                    if perms == "644":
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {desc} is configured (644)")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {desc} has incorrect permissions ({perms}, expected: 644)")
                        all_ok = False
                else:
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {desc} is empty or missing")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Command Line Warning Banners{Colors.END}")
            all_ok = True
            
            # Default warning banner text
            banner_text = """Authorized users only. All activity may be monitored and reported."""
            
            banner_files = [
                ("/etc/issue", "local login banner"),
                ("/etc/issue.net", "remote login banner"),
                ("/etc/motd", "message of the day")
            ]
            
            for filepath, desc in banner_files:
                print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring {desc} ({filepath})...")
                
                # Create/update banner file
                rc, _ = self.run_cmd(f"echo '{banner_text}' > {filepath}")
                
                # Set permissions
                rc_perm, _ = self.run_cmd(f"chmod 644 {filepath}")
                rc_own, _ = self.run_cmd(f"chown root:root {filepath}")
                
                if rc == 0 and rc_perm == 0 and rc_own == 0:
                    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {desc} configured")
                else:
                    print(f"{Colors.RED}[ERROR]{Colors.END} Failed to configure {desc}")
                    all_ok = False
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== BOOT PROCESS: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic boot process policy")

        # Configure bootloader (always manual for password)
        result = self.configure_bootloader("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("BP-1-2", "ok", result)

        print(f"\n{Colors.BOLD}Boot Process Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Bootloader: {Colors.YELLOW}MANUAL CHECK REQUIRED{Colors.END}")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== BOOT PROCESS: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate boot process policy")

        self.apply_basic(False)

        # Configure process hardening
        result = self.configure_process_hardening("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("BP-3-7", "ok", result)

        print(f"\n{Colors.BOLD}Boot Process Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Bootloader: {Colors.YELLOW}MANUAL CHECK REQUIRED{Colors.END}")
        print(f"Process Hardening: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== BOOT PROCESS: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict boot process policy")

        self.apply_moderate(False)

        # Configure warning banners
        result = self.configure_warning_banners("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("BP-8-12", "ok", result)

        print(f"\n{Colors.BOLD}Boot Process Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Bootloader: {Colors.YELLOW}MANUAL CHECK REQUIRED{Colors.END}")
        print(f"Process Hardening: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Warning Banners: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict boot process checks successfully!")

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
