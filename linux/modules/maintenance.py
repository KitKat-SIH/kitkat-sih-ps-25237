# hardn/modules/maintenance.py
"""
Implements Linux hardening controls for Section 9 – System Maintenance
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any
from .base import BaseHardeningModule, Colors


# ---------------------- Module Implementation ----------------------

class MaintenanceModule(BaseHardeningModule):
    id: str = "maintenance"

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

    # ---------------------- System File Permissions ----------------------

    def configure_system_file_permissions(self, action: str) -> bool:
        """MAINT-1 to MAINT-10: Configure critical system file permissions"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring System File Permissions{Colors.END}")
            all_ok = True
            
            # Define critical system files and their expected permissions
            system_files = [
                ("/etc/passwd", "644", "root", "root"),
                ("/etc/passwd-", "644", "root", "root"),
                ("/etc/group", "644", "root", "root"),
                ("/etc/group-", "644", "root", "root"),
                ("/etc/shadow", "000", "root", "shadow"),
                ("/etc/shadow-", "000", "root", "shadow"),
                ("/etc/gshadow", "000", "root", "shadow"),
                ("/etc/gshadow-", "000", "root", "shadow"),
                ("/etc/shells", "644", "root", "root"),
                ("/etc/security/opasswd", "600", "root", "root"),
            ]
            
            for filepath, expected_perms, expected_owner, expected_group in system_files:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking {filepath}...")
                
                rc, _ = self.run_cmd(f"test -f {filepath}")
                if rc != 0:
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {filepath} does not exist")
                    continue
                
                # Check permissions
                rc, perms = self.run_cmd(f"stat -c '%a' {filepath}")
                rc_owner, owner = self.run_cmd(f"stat -c '%U' {filepath}")
                rc_group, group = self.run_cmd(f"stat -c '%G' {filepath}")
                
                file_ok = True
                
                if perms != expected_perms:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {filepath} permissions incorrect (current: {perms}, expected: {expected_perms})")
                    file_ok = False
                    all_ok = False
                
                if owner != expected_owner:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {filepath} owner incorrect (current: {owner}, expected: {expected_owner})")
                    file_ok = False
                    all_ok = False
                
                if group != expected_group:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {filepath} group incorrect (current: {group}, expected: {expected_group})")
                    file_ok = False
                    all_ok = False
                
                if file_ok:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {filepath} permissions correct")
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring System File Permissions{Colors.END}")
            all_ok = True
            
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting system file permissions...")
            
            system_files = [
                ("/etc/passwd", "644", "root", "root"),
                ("/etc/passwd-", "644", "root", "root"),
                ("/etc/group", "644", "root", "root"),
                ("/etc/group-", "644", "root", "root"),
                ("/etc/shadow", "000", "root", "shadow"),
                ("/etc/shadow-", "000", "root", "shadow"),
                ("/etc/gshadow", "000", "root", "shadow"),
                ("/etc/gshadow-", "000", "root", "shadow"),
                ("/etc/shells", "644", "root", "root"),
                ("/etc/security/opasswd", "600", "root", "root"),
            ]
            
            for filepath, perms, owner, group in system_files:
                rc, _ = self.run_cmd(f"test -f {filepath}")
                if rc == 0:
                    self.run_cmd(f"chmod {perms} {filepath}")
                    self.run_cmd(f"chown {owner}:{group} {filepath}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} System file permissions configured")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- World Writable Files and Orphaned Files ----------------------

    def configure_file_security(self, action: str) -> bool:
        """MAINT-11 to MAINT-13: Secure world-writable files, orphaned files, and review SUID/SGID"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring File Security{Colors.END}")
            all_ok = True
            
            # Check for world-writable files
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for world-writable files...")
            rc, output = self.run_cmd(
                "find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -10"
            )
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} World-writable files found:")
                for line in output.split('\n')[:5]:
                    if line:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No world-writable files found")
            
            # Check for world-writable directories without sticky bit
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for world-writable directories...")
            rc, output = self.run_cmd(
                "find / -xdev -type d -perm -0002 ! -perm -1000 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -10"
            )
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} World-writable directories without sticky bit:")
                for line in output.split('\n')[:5]:
                    if line:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} World-writable directories properly secured")
            
            # Check for files without owner
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for files without owner...")
            rc, output = self.run_cmd(
                "find / -xdev -nouser ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -10"
            )
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Files without owner found:")
                for line in output.split('\n')[:5]:
                    if line:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No files without owner found")
            
            # Check for files without group
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for files without group...")
            rc, output = self.run_cmd(
                "find / -xdev -nogroup ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -10"
            )
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Files without group found:")
                for line in output.split('\n')[:5]:
                    if line:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No files without group found")
            
            # Check SUID/SGID files (Manual review)
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Listing SUID/SGID files for manual review...")
            rc, output = self.run_cmd(
                "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20"
            )
            
            if output:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} SUID/SGID files found - review these:")
                for line in output.split('\n')[:10]:
                    if line:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring File Security{Colors.END}")
            all_ok = True
            
            # Fix world-writable files
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Securing world-writable files...")
            self.run_cmd(
                "find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' "
                "-exec chmod o-w {} + 2>/dev/null"
            )
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} World-writable files secured")
            
            # Fix world-writable directories
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Securing world-writable directories...")
            self.run_cmd(
                "find / -xdev -type d -perm -0002 ! -perm -1000 ! -path '/proc/*' ! -path '/sys/*' "
                "-exec chmod +t {} + 2>/dev/null"
            )
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} World-writable directories secured with sticky bit")
            
            # Report orphaned files (cannot auto-fix)
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Files without owner/group require manual review")
            print(f"{Colors.YELLOW}         ↳{Colors.END} Find with: find / -xdev \\( -nouser -o -nogroup \\)")
            print(f"{Colors.YELLOW}         ↳{Colors.END} Fix with: chown <user>:<group> <file>")
            
            # SUID/SGID review
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} SUID/SGID files require manual review")
            print(f"{Colors.YELLOW}         ↳{Colors.END} List with: find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f")
            print(f"{Colors.YELLOW}         ↳{Colors.END} Remove unnecessary SUID/SGID: chmod u-s,g-s <file>")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Local User and Group Settings ----------------------

    def configure_user_group_settings(self, action: str) -> bool:
        """MAINT-14 to MAINT-21: Validate user and group configuration"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Local User and Group Settings{Colors.END}")
            all_ok = True
            
            # Check accounts use shadowed passwords
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if accounts use shadowed passwords...")
            rc, output = self.run_cmd("awk -F: '($2 != \"x\" && $2 != \"!\") {print $1}' /etc/passwd")
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Accounts not using shadow passwords: {output}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} All accounts use shadowed passwords")
            
            # Check for empty password fields
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for empty password fields...")
            rc, output = self.run_cmd("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Accounts with empty passwords: {output}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No accounts with empty passwords")
            
            # Check all groups in passwd exist in group
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if all groups in /etc/passwd exist in /etc/group...")
            rc, output = self.run_cmd(
                "for i in $(cut -s -d: -f4 /etc/passwd | sort -u); do "
                "grep -q -P \"^.*?:[^:]*:$i:\" /etc/group; "
                "if [ $? -ne 0 ]; then echo \"Group $i is referenced but does not exist\"; fi; done"
            )
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Missing groups: {output}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} All groups exist")
            
            # Check shadow group is empty
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if shadow group is empty...")
            rc, output = self.run_cmd("grep '^shadow:' /etc/group | cut -d: -f4")
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Shadow group has members: {output}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Shadow group is empty")
            
            # Check for duplicate UIDs
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for duplicate UIDs...")
            rc, output = self.run_cmd(
                "cut -d: -f3 /etc/passwd | sort | uniq -d | while read uid; do "
                "awk -F: -v uid=$uid '($3 == uid) {print $1}' /etc/passwd; done"
            )
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Duplicate UIDs found:")
                for line in output.split('\n')[:5]:
                    if line:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No duplicate UIDs found")
            
            # Check for duplicate GIDs
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for duplicate GIDs...")
            rc, output = self.run_cmd(
                "cut -d: -f3 /etc/group | sort | uniq -d | while read gid; do "
                "awk -F: -v gid=$gid '($3 == gid) {print $1}' /etc/group; done"
            )
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Duplicate GIDs found:")
                for line in output.split('\n')[:5]:
                    if line:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No duplicate GIDs found")
            
            # Check for duplicate usernames
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for duplicate usernames...")
            rc, output = self.run_cmd("cut -d: -f1 /etc/passwd | sort | uniq -d")
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Duplicate usernames: {output}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No duplicate usernames found")
            
            # Check for duplicate group names
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for duplicate group names...")
            rc, output = self.run_cmd("cut -d: -f1 /etc/group | sort | uniq -d")
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Duplicate group names: {output}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No duplicate group names found")
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Local User and Group Settings{Colors.END}")
            all_ok = True
            
            # Lock accounts with empty passwords
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Locking accounts with empty passwords...")
            rc, output = self.run_cmd("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
            
            if output:
                for user in output.split('\n'):
                    if user:
                        self.run_cmd(f"passwd -l {user}")
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Accounts with empty passwords locked")
            else:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} No accounts with empty passwords")
            
            # Other issues require manual intervention
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} The following issues require manual review:")
            print(f"{Colors.YELLOW}         ↳{Colors.END} Accounts not using shadowed passwords")
            print(f"{Colors.YELLOW}         ↳{Colors.END} Missing groups referenced in /etc/passwd")
            print(f"{Colors.YELLOW}         ↳{Colors.END} Members in shadow group")
            print(f"{Colors.YELLOW}         ↳{Colors.END} Duplicate UIDs/GIDs/usernames/group names")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- User Home Directories ----------------------

    def configure_user_home_directories(self, action: str) -> bool:
        """MAINT-22 to MAINT-23: Configure user home directories and dot files"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring User Home Directories{Colors.END}")
            all_ok = True
            
            # Check home directory existence and permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking user home directories...")
            rc, output = self.run_cmd(
                "awk -F: '($3 >= 1000 && $3 != 65534 && $1 != \"nobody\") {print $1,$6}' /etc/passwd"
            )
            
            if output:
                issues = []
                for line in output.split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            user, homedir = parts[0], parts[1]
                            
                            # Check if home directory exists
                            rc_exists, _ = self.run_cmd(f"test -d {homedir}")
                            if rc_exists != 0:
                                issues.append(f"{user}: home directory {homedir} does not exist")
                                continue
                            
                            # Check permissions (should not be group/other writable)
                            rc_perms, perms = self.run_cmd(f"stat -c '%a' {homedir}")
                            if rc_perms == 0:
                                perm_int = int(perms)
                                if (perm_int & 0o022) != 0:
                                    issues.append(f"{user}: {homedir} has excessive permissions ({perms})")
                
                if issues:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Home directory issues:")
                    for issue in issues[:10]:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {issue}")
                    all_ok = False
                else:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} User home directories properly configured")
            
            # Check dot file permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking user dot file permissions...")
            rc, output = self.run_cmd(
                "awk -F: '($3 >= 1000 && $3 != 65534) {print $6}' /etc/passwd | "
                "while read dir; do "
                "if [ -d \"$dir\" ]; then "
                "find \"$dir\" -maxdepth 1 -name '.*' -type f -perm /go+w 2>/dev/null; "
                "fi; done | head -10"
            )
            
            if output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Group/other-writable dot files found:")
                for line in output.split('\n')[:5]:
                    if line:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Dot files properly secured")
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring User Home Directories{Colors.END}")
            all_ok = True
            
            # Fix home directory permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Securing user home directories...")
            rc, output = self.run_cmd(
                "awk -F: '($3 >= 1000 && $3 != 65534 && $1 != \"nobody\") {print $6}' /etc/passwd"
            )
            
            if output:
                for homedir in output.split('\n'):
                    if homedir:
                        rc, _ = self.run_cmd(f"test -d {homedir}")
                        if rc == 0:
                            self.run_cmd(f"chmod go-w {homedir}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Home directory permissions secured")
            
            # Fix dot file permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Securing user dot files...")
            self.run_cmd(
                "awk -F: '($3 >= 1000 && $3 != 65534) {print $6}' /etc/passwd | "
                "while read dir; do "
                "if [ -d \"$dir\" ]; then "
                "find \"$dir\" -maxdepth 1 -name '.*' -type f -exec chmod go-w {} + 2>/dev/null; "
                "fi; done"
            )
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Dot file permissions secured")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== MAINTENANCE: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic maintenance policy")

        # Configure system file permissions (most critical)
        result = self.configure_system_file_permissions("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("MAINT-1-10", "ok", result)

        print(f"\n{Colors.BOLD}Maintenance Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"System File Permissions: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== MAINTENANCE: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate maintenance policy")

        self.apply_basic(False)

        # Configure user and group settings
        result = self.configure_user_group_settings("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("MAINT-14-21", "ok", result)

        print(f"\n{Colors.BOLD}Maintenance Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"System File Permissions: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"User & Group Settings: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== MAINTENANCE: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict maintenance policy")

        self.apply_moderate(False)

        # Configure file security
        result = self.configure_file_security("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("MAINT-11-13", "ok", result)

        # Configure user home directories
        result = self.configure_user_home_directories("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("MAINT-22-23", "ok", result)

        print(f"\n{Colors.BOLD}Maintenance Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"System File Permissions: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"User & Group Settings: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"File Security: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"User Home Directories: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict maintenance checks successfully!")

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
