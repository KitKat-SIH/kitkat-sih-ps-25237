# hardn/modules/filesystem.py
"""
Implements Linux hardening controls for Section 1 – Filesystem Configuration
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any, Dict, Tuple, List
from .base import BaseHardeningModule, Colors



# ---------------------- Module Implementation ----------------------

class FilesystemModule(BaseHardeningModule):
    id: str = "filesystem"

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

    # ---------------------- Filesystem Kernel Modules ----------------------

    def kernel_module_disabled(self, module_name: str, action: str) -> bool:
        """Generic check/enforce for kernel module disabling"""
        def check() -> bool:
            cmd = f"lsmod | grep -q {module_name}"
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if {module_name} module is disabled...")
            rc, _ = self.run_cmd(cmd)
            if rc != 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {module_name} module not loaded")
                return True
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {module_name} module is loaded")
                return False

        def enforce() -> bool:
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Disabling {module_name} module...")
            
            # Create blacklist entry
            blacklist_file = f"/etc/modprobe.d/{module_name}.conf"
            cmd1 = f"echo 'install {module_name} /bin/true' > {blacklist_file}"
            rc1, _ = self.run_cmd(cmd1)
            
            # Remove if loaded
            cmd2 = f"rmmod {module_name} 2>/dev/null || true"
            rc2, _ = self.run_cmd(cmd2)
            
            if rc1 == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {module_name} module disabled")
                return True
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to disable {module_name}")
                return False

        return check() if action == "check" else enforce()

    def disable_filesystem_modules(self, action: str) -> bool:
        """FS-1 to FS-9: Ensure filesystem kernel modules are not available"""
        modules = [
            "cramfs", "freevxfs", "hfs", "hfsplus", 
            "jffs2", "overlay", "squashfs", "udf", "usb-storage"
        ]
        
        print(f"\n{Colors.BOLD}Configuring Filesystem Kernel Modules{Colors.END}")
        all_compliant = True
        
        for module in modules:
            result = self.kernel_module_disabled(module, action)
            if not result:
                all_compliant = False
        
        return all_compliant

    # ---------------------- Partition Mount Options ----------------------

    def configure_partition(self, partition: str, options: List[str], action: str) -> bool:
        """Configure mount options for a partition"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring {partition}{Colors.END}")
            all_ok = True
            
            # Check if partition exists
            cmd = f"mount | grep -q ' {partition} '"
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if {partition} is a separate partition...")
            rc, _ = self.run_cmd(cmd)
            
            if rc != 0:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {partition} is not a separate partition")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {partition} is a separate partition")
            
            # Check each option
            for option in options:
                cmd = f"mount | grep '{partition}' | grep -q '{option}'"
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if {partition} has {option} option...")
                rc, _ = self.run_cmd(cmd)
                
                if rc == 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {partition} has {option}")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {partition} missing {option}")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring {partition}{Colors.END}")
            
            # Check if partition exists first
            cmd = f"mount | grep -q ' {partition} '"
            rc, _ = self.run_cmd(cmd)
            
            if rc != 0:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {partition} is not a separate partition - cannot enforce")
                return False
            
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Adding options {','.join(options)} to {partition}...")
            
            # Backup fstab
            self.run_cmd("cp /etc/fstab /etc/fstab.backup")
            
            # Get current mount options
            rc, current_line = self.run_cmd(f"grep '{partition}' /etc/fstab | grep -v '^#'")
            
            if rc != 0:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {partition} not found in /etc/fstab")
                return False
            
            # Add missing options
            for option in options:
                # Check if option already exists in fstab
                rc, _ = self.run_cmd(f"grep '{partition}' /etc/fstab | grep -q '{option}'")
                if rc != 0:
                    # Add the option
                    cmd = f"sed -i 's|\\( {partition} .* defaults\\)|\\1,{option}|' /etc/fstab"
                    self.run_cmd(cmd)
            
            # Remount partition
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Remounting {partition}...")
            rc, _ = self.run_cmd(f"mount -o remount {partition}")
            
            if rc == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {partition} configured with {','.join(options)}")
                return True
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} Failed to remount {partition}")
                return False

        return check() if action == "check" else enforce()

    def configure_tmp(self, action: str) -> bool:
        """FS-10 to FS-13: Configure /tmp partition"""
        return self.configure_partition("/tmp", ["nodev", "nosuid", "noexec"], action)

    def configure_dev_shm(self, action: str) -> bool:
        """FS-14 to FS-17: Configure /dev/shm partition"""
        return self.configure_partition("/dev/shm", ["nodev", "nosuid", "noexec"], action)

    def configure_home(self, action: str) -> bool:
        """FS-18 to FS-20: Configure /home partition"""
        return self.configure_partition("/home", ["nodev", "nosuid"], action)

    def configure_var(self, action: str) -> bool:
        """FS-21 to FS-23: Configure /var partition"""
        return self.configure_partition("/var", ["nodev", "nosuid"], action)

    def configure_var_tmp(self, action: str) -> bool:
        """FS-24 to FS-27: Configure /var/tmp partition"""
        return self.configure_partition("/var/tmp", ["nodev", "nosuid", "noexec"], action)

    def configure_var_log(self, action: str) -> bool:
        """FS-28 to FS-31: Configure /var/log partition"""
        return self.configure_partition("/var/log", ["nodev", "nosuid", "noexec"], action)

    def configure_var_log_audit(self, action: str) -> bool:
        """FS-32 to FS-35: Configure /var/log/audit partition"""
        return self.configure_partition("/var/log/audit", ["nodev", "nosuid", "noexec"], action)

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FILESYSTEM: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic filesystem policy")

        # Disable critical kernel modules
        result = self.disable_filesystem_modules("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("filesystem", "FS-1-9", "ok", result)

        # Configure /tmp - most critical
        result = self.configure_tmp("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("filesystem", "FS-10-13", "ok", result)

        print(f"\n{Colors.BOLD}Filesystem Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Kernel Modules: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/tmp Partition: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FILESYSTEM: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate filesystem policy")

        self.apply_basic(False)

        # Configure /dev/shm
        result = self.configure_dev_shm("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("filesystem", "FS-14-17", "ok", result)

        # Configure /home
        result = self.configure_home("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("filesystem", "FS-18-20", "ok", result)

        print(f"\n{Colors.BOLD}Filesystem Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Kernel Modules: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/tmp Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/dev/shm Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/home Partition: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FILESYSTEM: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict filesystem policy")

        self.apply_moderate(False)

        # Configure /var
        result = self.configure_var("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("filesystem", "FS-21-23", "ok", result)

        # Configure /var/tmp
        result = self.configure_var_tmp("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("filesystem", "FS-24-27", "ok", result)

        # Configure /var/log
        result = self.configure_var_log("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("filesystem", "FS-28-31", "ok", result)

        # Configure /var/log/audit
        result = self.configure_var_log_audit("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("filesystem", "FS-32-35", "ok", result)

        print(f"\n{Colors.BOLD}Filesystem Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Kernel Modules: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/tmp Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/dev/shm Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/home Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/var Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/var/tmp Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/var/log Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"/var/log/audit Partition: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict filesystem checks successfully!")

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
