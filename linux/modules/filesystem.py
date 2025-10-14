# hardn/modules/filesystem.py
"""
Implements Linux hardening controls for Section 1 – Filesystem Configuration
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any, List
from .base import BaseHardeningModule, Colors


# ---------------------- Module Implementation ----------------------

class FilesystemModule(BaseHardeningModule):
    id: str = "filesystem"

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

    def configure_partition(self, partition: str, options: List[str], action: str, 
                          use_fstab: bool = True) -> bool:
        """
        Configure mount options for a partition.
        
        Args:
            partition: Mount point path (e.g., "/tmp", "/dev/shm")
            options: List of mount options to enforce (e.g., ["nodev", "nosuid", "noexec"])
            action: "check" or "enforce"
            use_fstab: If False, only check mount output and use remount (for systemd-managed mounts)
        """
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring {partition}{Colors.END}")
            all_ok = True
            
            # Check if partition is currently mounted
            cmd = f"mount | grep -E '\\s+{partition}\\s+'"
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if {partition} is mounted...")
            rc, mount_output = self.run_cmd(cmd)
            
            if rc != 0:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {partition} is not mounted")
                return False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {partition} is mounted")
            
            # Check each option in current mount
            for option in options:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if {partition} has {option} option...")
                
                if option in mount_output:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {partition} has {option}")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {partition} missing {option}")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring {partition}{Colors.END}")
            
            # Check if partition is mounted
            cmd = f"mount | grep -E '\\s+{partition}\\s+'"
            rc, mount_output = self.run_cmd(cmd)
            
            if rc != 0:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {partition} is not mounted - cannot enforce")
                return False
            
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring {partition} with options: {','.join(options)}...")
            
            # If this is a systemd-managed mount (like /tmp, /dev/shm, /var/tmp)
            if not use_fstab:
                # Just remount with desired options
                options_str = ",".join(options)
                print(f"{Colors.BLUE}[WORKING]{Colors.END} Remounting {partition} (systemd-managed)...")
                rc, _ = self.run_cmd(f"mount -o remount,{options_str} {partition}")
                
                if rc == 0:
                    print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {partition} remounted with {options_str}")
                    print(f"{Colors.YELLOW}[INFO]{Colors.END} Note: Changes are not persistent across reboots")
                    print(f"{Colors.YELLOW}      ↳{Colors.END} To make persistent, add to /etc/fstab manually")
                    return True
                else:
                    print(f"{Colors.RED}[ERROR]{Colors.END} Failed to remount {partition}")
                    return False
            
            # For traditional partitions (like /home), use fstab
            else:
                # Backup fstab
                self.run_cmd("cp /etc/fstab /etc/fstab.backup 2>/dev/null")
                
                # Check if partition is in fstab
                rc, current_line = self.run_cmd(f"grep -E '^[^#].*\\s+{partition}\\s+' /etc/fstab")
                
                if rc != 0:
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {partition} not found in /etc/fstab")
                    print(f"{Colors.YELLOW}      ↳{Colors.END} Add manually: UUID=<uuid> {partition} <fstype> defaults,{','.join(options)} 0 2")
                    return False
                
                # Add missing options to fstab
                for option in options:
                    # Check if option already exists in fstab
                    rc, _ = self.run_cmd(f"grep -E '^[^#].*\\s+{partition}\\s+' /etc/fstab | grep -q '{option}'")
                    if rc != 0:
                        # Add the option
                        cmd = f"sed -i 's|\\(\\s{partition}\\s.*defaults\\)|\\1,{option}|' /etc/fstab"
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
        """FS-10 to FS-13: Configure /tmp partition (systemd-managed)"""
        return self.configure_partition("/tmp", ["nodev", "nosuid", "noexec"], action, use_fstab=False)

    def configure_dev_shm(self, action: str) -> bool:
        """FS-14 to FS-17: Configure /dev/shm partition (systemd-managed)"""
        return self.configure_partition("/dev/shm", ["nodev", "nosuid", "noexec"], action, use_fstab=False)

    def configure_home(self, action: str) -> bool:
        """FS-18 to FS-20: Configure /home partition (traditional fstab)"""
        return self.configure_partition("/home", ["nodev", "nosuid"], action, use_fstab=True)

    def configure_var(self, action: str) -> bool:
        """FS-21 to FS-23: Configure /var partition (systemd-managed)"""
        return self.configure_partition("/var", ["nodev", "nosuid"], action, use_fstab=False)

    def configure_var_tmp(self, action: str) -> bool:
        """FS-24 to FS-27: Configure /var/tmp partition (systemd-managed)"""
        return self.configure_partition("/var/tmp", ["nodev", "nosuid", "noexec"], action, use_fstab=False)

    def configure_var_log(self, action: str) -> bool:
        """FS-28 to FS-31: Configure /var/log partition (systemd-managed)"""
        return self.configure_partition("/var/log", ["nodev", "nosuid", "noexec"], action, use_fstab=False)

    def configure_var_log_audit(self, action: str) -> bool:
        """FS-32 to FS-35: Configure /var/log/audit partition (systemd-managed)"""
        return self.configure_partition("/var/log/audit", ["nodev", "nosuid", "noexec"], action, use_fstab=False)

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FILESYSTEM: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic filesystem policy")

        # Disable critical kernel modules (check then enforce if needed)
        if self.ctx.get("mode") == "audit":
            mods_ok = self.disable_filesystem_modules("check")
        else:
            mods_ok = self.disable_filesystem_modules("check")
            if not mods_ok:
                mods_ok = self.disable_filesystem_modules("enforce")
        self.add_result("FS-1-9", "ok", mods_ok)

        # Configure /tmp - most critical (check then enforce if needed)
        if self.ctx.get("mode") == "audit":
            tmp_ok = self.configure_tmp("check")
        else:
            tmp_ok = self.configure_tmp("check")
            if not tmp_ok:
                tmp_ok = self.configure_tmp("enforce")
        self.add_result("FS-10-13", "ok", tmp_ok)

        print(f"\n{Colors.BOLD}Filesystem Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Kernel Modules: {Colors.GREEN}COMPLIANT{Colors.END}" if mods_ok else f"Kernel Modules: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/tmp Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if tmp_ok else f"/tmp Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        if mods_ok and tmp_ok:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed basic filesystem checks successfully!")
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Basic filesystem checks have non-compliances")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FILESYSTEM: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate filesystem policy")

        self.apply_basic(True)

        # Configure /dev/shm (check then enforce if needed)
        if self.ctx.get("mode") == "audit":
            devshm_ok = self.configure_dev_shm("check")
        else:
            devshm_ok = self.configure_dev_shm("check")
            if not devshm_ok:
                devshm_ok = self.configure_dev_shm("enforce")
        self.add_result("FS-14-17", "ok", devshm_ok)

        # Configure /home (check then enforce if needed)
        if self.ctx.get("mode") == "audit":
            home_ok = self.configure_home("check")
        else:
            home_ok = self.configure_home("check")
            if not home_ok:
                home_ok = self.configure_home("enforce")
        self.add_result("FS-18-20", "ok", home_ok)

        print(f"\n{Colors.BOLD}Filesystem Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        # Re-check basic items for accurate summary
        mods_ok = self.disable_filesystem_modules("check")
        tmp_ok = self.configure_tmp("check")
        print(f"Kernel Modules: {Colors.GREEN}COMPLIANT{Colors.END}" if mods_ok else f"Kernel Modules: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/tmp Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if tmp_ok else f"/tmp Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/dev/shm Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if devshm_ok else f"/dev/shm Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/home Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if home_ok else f"/home Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        if all([mods_ok, tmp_ok, devshm_ok, home_ok]):
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed moderate filesystem checks successfully!")
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Moderate filesystem checks have non-compliances")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== FILESYSTEM: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict filesystem policy")

        self.apply_moderate(True)

        # Configure /var (check then enforce if needed)
        if self.ctx.get("mode") == "audit":
            var_ok = self.configure_var("check")
        else:
            var_ok = self.configure_var("check")
            if not var_ok:
                var_ok = self.configure_var("enforce")
        self.add_result("FS-21-23", "ok", var_ok)

        # Configure /var/tmp (check then enforce if needed)
        if self.ctx.get("mode") == "audit":
            vartmp_ok = self.configure_var_tmp("check")
        else:
            vartmp_ok = self.configure_var_tmp("check")
            if not vartmp_ok:
                vartmp_ok = self.configure_var_tmp("enforce")
        self.add_result("FS-24-27", "ok", vartmp_ok)

        # Configure /var/log (check then enforce if needed)
        if self.ctx.get("mode") == "audit":
            varlog_ok = self.configure_var_log("check")
        else:
            varlog_ok = self.configure_var_log("check")
            if not varlog_ok:
                varlog_ok = self.configure_var_log("enforce")
        self.add_result("FS-28-31", "ok", varlog_ok)

        # Configure /var/log/audit (check then enforce if needed)
        if self.ctx.get("mode") == "audit":
            varlogaudit_ok = self.configure_var_log_audit("check")
        else:
            varlogaudit_ok = self.configure_var_log_audit("check")
            if not varlogaudit_ok:
                varlogaudit_ok = self.configure_var_log_audit("enforce")
        self.add_result("FS-32-35", "ok", varlogaudit_ok)

        print(f"\n{Colors.BOLD}Filesystem Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        # Re-check earlier items for accurate summary
        mods_ok = self.disable_filesystem_modules("check")
        tmp_ok = self.configure_tmp("check")
        devshm_ok = self.configure_dev_shm("check")
        home_ok = self.configure_home("check")
        print(f"Kernel Modules: {Colors.GREEN}COMPLIANT{Colors.END}" if mods_ok else f"Kernel Modules: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/tmp Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if tmp_ok else f"/tmp Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/dev/shm Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if devshm_ok else f"/dev/shm Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/home Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if home_ok else f"/home Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/var Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if var_ok else f"/var Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/var/tmp Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if vartmp_ok else f"/var/tmp Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/var/log Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if varlog_ok else f"/var/log Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        print(f"/var/log/audit Partition: {Colors.GREEN}COMPLIANT{Colors.END}" if varlogaudit_ok else f"/var/log/audit Partition: {Colors.RED}NON-COMPLIANT{Colors.END}")
        if all([mods_ok, tmp_ok, devshm_ok, home_ok, var_ok, vartmp_ok, varlog_ok, varlogaudit_ok]):
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict filesystem checks successfully!")
        else:
            print(f"{Colors.RED}[ERROR]{Colors.END} Strict filesystem checks have non-compliances")

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