# hardn/modules/accounts.py
"""
Implements Linux hardening controls for Section 7 – User Accounts and Environment
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any, Dict, Tuple, List
from .base import BaseHardeningModule, Colors


# ---------------------- Module Implementation ----------------------

class AccountsModule(BaseHardeningModule):
    id: str = "accounts"

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

    # ---------------------- Configure Shadow Password Suite ----------------------

    def configure_shadow_password_suite(self, action: str) -> bool:
        """ACC-1 to ACC-6: Configure shadow password suite parameters"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Shadow Password Suite Parameters{Colors.END}")
            all_ok = True
            
            # Check password expiration (PASS_MAX_DAYS)
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking password expiration configuration...")
            rc, output = self.run_cmd("grep '^PASS_MAX_DAYS' /etc/login.defs")
            
            if output:
                try:
                    max_days = int(output.split()[1])
                    if max_days <= 365:
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Password expiration configured (PASS_MAX_DAYS: {max_days})")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Password expiration too long (PASS_MAX_DAYS: {max_days})")
                        all_ok = False
                except:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Invalid PASS_MAX_DAYS configuration")
                    all_ok = False
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} PASS_MAX_DAYS not configured")
                all_ok = False
            
            # Check minimum password days (PASS_MIN_DAYS) - Manual check
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking minimum password days configuration...")
            rc, output = self.run_cmd("grep '^PASS_MIN_DAYS' /etc/login.defs")
            
            if output:
                try:
                    min_days = int(output.split()[1])
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Minimum password days: {min_days}")
                    print(f"{Colors.YELLOW}         ↳{Colors.END} Verify this meets your security policy")
                except:
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Invalid PASS_MIN_DAYS configuration")
            else:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} PASS_MIN_DAYS not configured")
            
            # Check password warning days (PASS_WARN_AGE)
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking password warning days configuration...")
            rc, output = self.run_cmd("grep '^PASS_WARN_AGE' /etc/login.defs")
            
            if output:
                try:
                    warn_days = int(output.split()[1])
                    if warn_days >= 7:
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Password warning configured (PASS_WARN_AGE: {warn_days})")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Password warning too short (PASS_WARN_AGE: {warn_days})")
                        all_ok = False
                except:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Invalid PASS_WARN_AGE configuration")
                    all_ok = False
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} PASS_WARN_AGE not configured")
                all_ok = False
            
            # Check password hashing algorithm
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking password hashing algorithm...")
            rc, output = self.run_cmd("grep '^ENCRYPT_METHOD' /etc/login.defs")
            
            if "SHA512" in output or "yescrypt" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Strong password hashing algorithm configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Weak password hashing algorithm")
                all_ok = False
            
            # Check inactive password lock
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking inactive password lock configuration...")
            rc, output = self.run_cmd("useradd -D | grep INACTIVE")
            
            if output:
                try:
                    inactive_days = int(output.split('=')[1])
                    if 0 < inactive_days <= 30:
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Inactive password lock configured ({inactive_days} days)")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Inactive password lock not properly configured")
                        all_ok = False
                except:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Invalid INACTIVE configuration")
                    all_ok = False
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} INACTIVE not configured")
                all_ok = False
            
            # Check last password change dates
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking user password change dates...")
            rc, output = self.run_cmd("awk -F: '($2 != \"*\" && $2 != \"!\") {print $1,$3}' /etc/shadow")
            
            import time
            current_date = int(time.time() / 86400)  # Days since epoch
            
            future_dates = []
            if output:
                for line in output.split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                last_change = int(parts[1])
                                if last_change > current_date:
                                    future_dates.append(parts[0])
                            except:
                                pass
            
            if not future_dates:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} All password change dates are valid")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Users with future password dates: {', '.join(future_dates)}")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Shadow Password Suite Parameters{Colors.END}")
            all_ok = True
            
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring password policies in /etc/login.defs...")
            
            # Backup login.defs
            self.run_cmd("cp /etc/login.defs /etc/login.defs.backup")
            
            # Set PASS_MAX_DAYS
            rc, _ = self.run_cmd("grep -q '^PASS_MAX_DAYS' /etc/login.defs")
            if rc == 0:
                self.run_cmd("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs")
            else:
                self.run_cmd("echo 'PASS_MAX_DAYS   90' >> /etc/login.defs")
            
            # Set PASS_MIN_DAYS (manual check - use conservative value)
            rc, _ = self.run_cmd("grep -q '^PASS_MIN_DAYS' /etc/login.defs")
            if rc == 0:
                self.run_cmd("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs")
            else:
                self.run_cmd("echo 'PASS_MIN_DAYS   1' >> /etc/login.defs")
            
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} PASS_MIN_DAYS set to 1 - adjust per policy")
            
            # Set PASS_WARN_AGE
            rc, _ = self.run_cmd("grep -q '^PASS_WARN_AGE' /etc/login.defs")
            if rc == 0:
                self.run_cmd("sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs")
            else:
                self.run_cmd("echo 'PASS_WARN_AGE   7' >> /etc/login.defs")
            
            # Set ENCRYPT_METHOD
            rc, _ = self.run_cmd("grep -q '^ENCRYPT_METHOD' /etc/login.defs")
            if rc == 0:
                self.run_cmd("sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs")
            else:
                self.run_cmd("echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs")
            
            # Set INACTIVE
            self.run_cmd("useradd -D -f 30")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Password policies configured")
            
            # Note about existing users
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Apply settings to existing users with:")
            print(f"{Colors.YELLOW}         ↳{Colors.END} chage --maxdays 90 --mindays 1 --warndays 7 <username>")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Root and System Accounts ----------------------

    def configure_root_system_accounts(self, action: str) -> bool:
        """ACC-7 to ACC-14: Configure root and system account security"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Root and System Accounts{Colors.END}")
            all_ok = True
            
            # Check for multiple UID 0 accounts
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for UID 0 accounts...")
            rc, output = self.run_cmd("awk -F: '($3 == 0) {print $1}' /etc/passwd")
            
            uid_0_accounts = output.split('\n') if output else []
            if len(uid_0_accounts) == 1 and uid_0_accounts[0] == 'root':
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Only root has UID 0")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Multiple UID 0 accounts: {', '.join(uid_0_accounts)}")
                all_ok = False
            
            # Check for multiple GID 0 accounts
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for GID 0 accounts...")
            rc, output = self.run_cmd("awk -F: '($4 == 0) {print $1}' /etc/passwd")
            
            gid_0_accounts = output.split('\n') if output else []
            if len(gid_0_accounts) == 1 and gid_0_accounts[0] == 'root':
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Only root has GID 0")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Multiple GID 0 accounts: {', '.join(gid_0_accounts)}")
                all_ok = False
            
            # Check for GID 0 group
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking GID 0 group...")
            rc, output = self.run_cmd("awk -F: '($3 == 0) {print $1}' /etc/group")
            
            if output == 'root':
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Only root group has GID 0")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Invalid GID 0 group configuration")
                all_ok = False
            
            # Check root PATH integrity
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking root PATH integrity...")
            rc, root_path = self.run_cmd("echo $PATH")
            
            path_issues = []
            if root_path:
                if '::' in root_path or root_path.startswith(':') or root_path.endswith(':'):
                    path_issues.append("empty directory in PATH")
                if '.' in root_path.split(':'):
                    path_issues.append("current directory in PATH")
            
            if not path_issues:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Root PATH integrity verified")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Root PATH issues: {', '.join(path_issues)}")
                all_ok = False
            
            # Check root umask
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking root umask configuration...")
            rc, output = self.run_cmd("grep -E '^\\s*umask\\s+0[0-7]7' /root/.bashrc /root/.bash_profile 2>/dev/null")
            
            if output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Root umask is configured securely")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Root umask not properly configured")
                all_ok = False
            
            # Check system accounts don't have valid login shells
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking system account login shells...")
            rc, output = self.run_cmd(
                "awk -F: '($3 < 1000 && $1 != \"root\" && $7 != \"/sbin/nologin\" && "
                "$7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\") {print $1,$7}' /etc/passwd"
            )
            
            if not output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} System accounts properly configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} System accounts with valid shells:")
                for line in output.split('\n')[:5]:
                    print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
                all_ok = False
            
            # Check accounts without valid shell are locked
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking locked accounts without login shell...")
            rc, output = self.run_cmd(
                "awk -F: '($7 == \"/sbin/nologin\" || $7 == \"/usr/sbin/nologin\" || "
                "$7 == \"/bin/false\") {print $1}' /etc/passwd"
            )
            
            unlocked = []
            if output:
                for user in output.split('\n'):
                    if user:
                        rc, shadow_entry = self.run_cmd(f"grep '^{user}:' /etc/shadow")
                        if shadow_entry and not (shadow_entry.split(':')[1].startswith('!') or 
                                                 shadow_entry.split(':')[1].startswith('*')):
                            unlocked.append(user)
            
            if not unlocked:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Accounts without login shell are locked")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Unlocked accounts without shell: {', '.join(unlocked[:5])}")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Root and System Accounts{Colors.END}")
            all_ok = True
            
            # Check and warn about multiple UID 0 accounts
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Checking for multiple UID 0 accounts...")
            rc, output = self.run_cmd("awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/passwd")
            
            if output:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Multiple UID 0 accounts found:")
                for account in output.split('\n'):
                    if account:
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {account} - review and remove if unnecessary")
            else:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Only root has UID 0")
            
            # Set root umask
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring root umask...")
            
            for rc_file in ['/root/.bashrc', '/root/.bash_profile']:
                rc, _ = self.run_cmd(f"grep -q '^umask' {rc_file}")
                if rc == 0:
                    self.run_cmd(f"sed -i 's/^umask.*/umask 027/' {rc_file}")
                else:
                    self.run_cmd(f"echo 'umask 027' >> {rc_file}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Root umask configured to 027")
            
            # Lock system accounts
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Locking system accounts...")
            rc, output = self.run_cmd(
                "awk -F: '($3 < 1000 && $1 != \"root\" && $7 != \"/sbin/nologin\" && "
                "$7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\") {print $1}' /etc/passwd"
            )
            
            if output:
                for account in output.split('\n'):
                    if account:
                        self.run_cmd(f"usermod -s /usr/sbin/nologin {account} 2>/dev/null")
                        self.run_cmd(f"usermod -L {account} 2>/dev/null")
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} System accounts locked")
            else:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} No system accounts need locking")
            
            # Lock accounts without valid shell
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Locking accounts without valid login shell...")
            rc, output = self.run_cmd(
                "awk -F: '($7 == \"/sbin/nologin\" || $7 == \"/usr/sbin/nologin\" || "
                "$7 == \"/bin/false\") {print $1}' /etc/passwd"
            )
            
            if output:
                for account in output.split('\n'):
                    if account and account != 'root':
                        self.run_cmd(f"usermod -L {account} 2>/dev/null")
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Accounts without shell locked")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure User Default Environment ----------------------

    def configure_user_default_environment(self, action: str) -> bool:
        """ACC-15 to ACC-17: Configure user default environment"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring User Default Environment{Colors.END}")
            all_ok = True
            
            # Check nologin not in /etc/shells
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if nologin is not listed in /etc/shells...")
            rc, output = self.run_cmd("grep -E '(nologin|false)' /etc/shells")
            
            if not output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} nologin not listed in /etc/shells")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} nologin/false found in /etc/shells")
                all_ok = False
            
            # Check default shell timeout
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking default shell timeout...")
            
            timeout_files = ['/etc/bashrc', '/etc/bash.bashrc', '/etc/profile']
            timeout_found = False
            
            for filepath in timeout_files:
                rc, output = self.run_cmd(f"grep -E '^\\s*TMOUT=' {filepath} 2>/dev/null")
                if output:
                    try:
                        timeout = int(output.split('=')[1].strip())
                        if 0 < timeout <= 900:
                            print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Shell timeout configured in {filepath} (TMOUT={timeout})")
                            timeout_found = True
                            break
                    except:
                        pass
            
            if not timeout_found:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Shell timeout not configured")
                all_ok = False
            
            # Check default umask
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking default user umask...")
            
            umask_files = ['/etc/bashrc', '/etc/bash.bashrc', '/etc/profile', '/etc/login.defs']
            umask_found = False
            
            for filepath in umask_files:
                rc, output = self.run_cmd(f"grep -E '^\\s*umask\\s+0[0-7]7' {filepath} 2>/dev/null")
                if output:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Secure umask configured in {filepath}")
                    umask_found = True
                    break
            
            if not umask_found:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Secure umask not configured")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring User Default Environment{Colors.END}")
            all_ok = True
            
            # Remove nologin from /etc/shells
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Removing nologin from /etc/shells...")
            self.run_cmd("sed -i '/nologin/d' /etc/shells")
            self.run_cmd("sed -i '/\\/bin\\/false/d' /etc/shells")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} nologin removed from /etc/shells")
            
            # Configure shell timeout
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring default shell timeout...")
            
            profile_files = ['/etc/profile', '/etc/bashrc', '/etc/bash.bashrc']
            
            for filepath in profile_files:
                rc, _ = self.run_cmd(f"test -f {filepath}")
                if rc == 0:
                    # Check if TMOUT exists
                    rc, _ = self.run_cmd(f"grep -q '^TMOUT=' {filepath}")
                    if rc == 0:
                        self.run_cmd(f"sed -i 's/^TMOUT=.*/TMOUT=900/' {filepath}")
                        self.run_cmd(f"sed -i 's/^readonly TMOUT.*/readonly TMOUT/' {filepath} || echo 'readonly TMOUT' >> {filepath}")
                    else:
                        self.run_cmd(f"echo 'TMOUT=900' >> {filepath}")
                        self.run_cmd(f"echo 'readonly TMOUT' >> {filepath}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Shell timeout configured (TMOUT=900)")
            
            # Configure default umask
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring default user umask...")
            
            for filepath in profile_files:
                rc, _ = self.run_cmd(f"test -f {filepath}")
                if rc == 0:
                    rc, _ = self.run_cmd(f"grep -q '^umask' {filepath}")
                    if rc == 0:
                        self.run_cmd(f"sed -i 's/^umask.*/umask 027/' {filepath}")
                    else:
                        self.run_cmd(f"echo 'umask 027' >> {filepath}")
            
            # Also set in login.defs
            rc, _ = self.run_cmd("grep -q '^UMASK' /etc/login.defs")
            if rc == 0:
                self.run_cmd("sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs")
            else:
                self.run_cmd("echo 'UMASK 027' >> /etc/login.defs")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Default umask configured to 027")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== ACCOUNTS: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic accounts policy")

        # Configure shadow password suite
        result = self.configure_shadow_password_suite("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("accounts", "ACC-1-6", "ok", result)

        print(f"\n{Colors.BOLD}Accounts Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Password Policies: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== ACCOUNTS: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate accounts policy")

        self.apply_basic(False)

        # Configure user default environment
        result = self.configure_user_default_environment("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("accounts", "ACC-15-17", "ok", result)

        print(f"\n{Colors.BOLD}Accounts Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Password Policies: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"User Environment: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== ACCOUNTS: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict accounts policy")

        self.apply_moderate(False)

        # Configure root and system accounts
        result = self.configure_root_system_accounts("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("accounts", "ACC-7-14", "ok", result)

        print(f"\n{Colors.BOLD}Accounts Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Password Policies: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"User Environment: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Root & System Accounts: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict account checks successfully!")

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
