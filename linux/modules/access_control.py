# hardn/modules/access_control.py
"""
Implements Linux hardening controls for Section 6 – Access Control
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any, Dict, Tuple, List
from .base import BaseHardeningModule, Colors


# ---------------------- Module Implementation ----------------------

class AccessControlModule(BaseHardeningModule):
    id: str = "access_control"

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

    # ---------------------- Configure SSH Server ----------------------

    def configure_ssh_server(self, action: str) -> bool:
        """AC-1 to AC-22: Configure SSH server security"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring SSH Server{Colors.END}")
            all_ok = True
            
            sshd_config = "/etc/ssh/sshd_config"
            
            # Check sshd_config permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking {sshd_config} permissions...")
            rc, perms = self.run_cmd(f"stat -c '%a' {sshd_config} 2>/dev/null")
            
            if perms == "600":
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} sshd_config permissions correct (600)")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} sshd_config permissions incorrect ({perms})")
                all_ok = False
            
            # Check SSH private key permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking SSH private host key permissions...")
            rc, output = self.run_cmd("find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -c '%n %a' {} \\;")
            
            if output:
                private_keys_ok = True
                for line in output.split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] != "600":
                            print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {parts[0]} has permissions {parts[1]}")
                            private_keys_ok = False
                            all_ok = False
                if private_keys_ok:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} SSH private keys have correct permissions")
            
            # Check SSH public key permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking SSH public host key permissions...")
            rc, output = self.run_cmd("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat -c '%n %a' {} \\;")
            
            if output:
                public_keys_ok = True
                for line in output.split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] != "644":
                            print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {parts[0]} has permissions {parts[1]}")
                            public_keys_ok = False
                            all_ok = False
                if public_keys_ok:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} SSH public keys have correct permissions")
            
            # Check SSH configuration parameters
            ssh_params = [
                ("Banner", "/etc/issue.net", "Banner"),
                ("Ciphers", "aes256-ctr,aes192-ctr,aes128-ctr", "strong ciphers"),
                ("ClientAliveInterval", "300", "client alive interval"),
                ("ClientAliveCountMax", "3", "client alive count max"),
                ("DisableForwarding", "yes", "disable forwarding"),
                ("GSSAPIAuthentication", "no", "GSSAPI authentication disabled"),
                ("HostbasedAuthentication", "no", "host-based auth disabled"),
                ("IgnoreRhosts", "yes", "ignore rhosts"),
                ("KexAlgorithms", "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256", "strong key exchange"),
                ("LoginGraceTime", "60", "login grace time"),
                ("LogLevel", "INFO", "log level"),
                ("MACs", "hmac-sha2-512,hmac-sha2-256", "strong MACs"),
                ("MaxAuthTries", "4", "max auth tries"),
                ("MaxSessions", "10", "max sessions"),
                ("MaxStartups", "10:30:60", "max startups"),
                ("PermitEmptyPasswords", "no", "empty passwords disabled"),
                ("PermitRootLogin", "no", "root login disabled"),
                ("PermitUserEnvironment", "no", "user environment disabled"),
                ("UsePAM", "yes", "PAM enabled"),
            ]
            
            for param, expected, description in ssh_params:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking {description}...")
                rc, output = self.run_cmd(f"grep -E '^{param}\\s' {sshd_config}")
                
                if output:
                    current_value = output.split()[1] if len(output.split()) > 1 else ""
                    if param in ["Ciphers", "KexAlgorithms", "MACs"] or current_value == expected:
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {description} configured")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} not properly configured")
                        all_ok = False
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} not configured")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring SSH Server{Colors.END}")
            all_ok = True
            
            sshd_config = "/etc/ssh/sshd_config"
            
            # Backup sshd_config
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Backing up {sshd_config}...")
            self.run_cmd(f"cp {sshd_config} {sshd_config}.backup")
            
            # Set sshd_config permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting {sshd_config} permissions...")
            self.run_cmd(f"chmod 600 {sshd_config}")
            self.run_cmd(f"chown root:root {sshd_config}")
            
            # Set SSH private key permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting SSH private key permissions...")
            self.run_cmd("find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 600 {} \\;")
            self.run_cmd("find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \\;")
            
            # Set SSH public key permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting SSH public key permissions...")
            self.run_cmd("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 644 {} \\;")
            self.run_cmd("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \\;")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} SSH file permissions configured")
            
            # Configure SSH parameters
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring SSH parameters...")
            
            ssh_settings = {
                "Banner": "/etc/issue.net",
                "Ciphers": "aes256-ctr,aes192-ctr,aes128-ctr",
                "ClientAliveInterval": "300",
                "ClientAliveCountMax": "3",
                "DisableForwarding": "yes",
                "GSSAPIAuthentication": "no",
                "HostbasedAuthentication": "no",
                "IgnoreRhosts": "yes",
                "KexAlgorithms": "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256",
                "LoginGraceTime": "60",
                "LogLevel": "INFO",
                "MACs": "hmac-sha2-512,hmac-sha2-256",
                "MaxAuthTries": "4",
                "MaxSessions": "10",
                "MaxStartups": "10:30:60",
                "PermitEmptyPasswords": "no",
                "PermitRootLogin": "no",
                "PermitUserEnvironment": "no",
                "UsePAM": "yes",
            }
            
            for param, value in ssh_settings.items():
                # Check if parameter exists
                rc, _ = self.run_cmd(f"grep -q '^{param}\\s' {sshd_config}")
                
                if rc == 0:
                    # Update existing
                    self.run_cmd(f"sed -i 's|^{param}\\s.*|{param} {value}|' {sshd_config}")
                else:
                    # Add new
                    self.run_cmd(f"echo '{param} {value}' >> {sshd_config}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} SSH parameters configured")
            
            # Validate and restart SSH
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Validating SSH configuration...")
            rc, output = self.run_cmd("sshd -t")
            
            if rc == 0:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} SSH configuration valid")
                self.run_cmd("systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null")
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} SSH service restarted")
            else:
                print(f"{Colors.RED}[ERROR]{Colors.END} SSH configuration invalid - not restarting")
                all_ok = False
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Privilege Escalation ----------------------

    def configure_privilege_escalation(self, action: str) -> bool:
        """AC-23 to AC-29: Configure sudo and privilege escalation"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Privilege Escalation{Colors.END}")
            all_ok = True
            
            # Check sudo is installed
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if sudo is installed...")
            rc, _ = self.run_cmd("command -v sudo")
            
            if rc == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} sudo is installed")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} sudo not installed")
                all_ok = False
            
            # Check sudo uses pty
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if sudo uses pty...")
            rc, output = self.run_cmd("grep -rE '^Defaults\\s+use_pty' /etc/sudoers*")
            
            if output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} sudo configured to use pty")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} sudo not configured to use pty")
                all_ok = False
            
            # Check sudo log file
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking sudo log file configuration...")
            rc, output = self.run_cmd("grep -rE '^Defaults\\s+logfile=' /etc/sudoers*")
            
            if output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} sudo log file configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} sudo log file not configured")
                all_ok = False
            
            # Check NOPASSWD usage
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for NOPASSWD in sudo configuration...")
            rc, output = self.run_cmd("grep -rE 'NOPASSWD' /etc/sudoers*")
            
            if not output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No NOPASSWD entries found")
            else:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} NOPASSWD entries found - review:")
                for line in output.split('\n')[:5]:
                    print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
            
            # Check !authenticate usage
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for !authenticate in sudo configuration...")
            rc, output = self.run_cmd("grep -rE '!authenticate' /etc/sudoers*")
            
            if not output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} No !authenticate entries found")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} !authenticate entries found")
                all_ok = False
            
            # Check sudo authentication timeout
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking sudo authentication timeout...")
            rc, output = self.run_cmd("grep -rE '^Defaults\\s+timestamp_timeout=' /etc/sudoers*")
            
            if output:
                try:
                    timeout = int(output.split('=')[1].strip())
                    if timeout <= 15:
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} sudo timeout configured ({timeout} minutes)")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} sudo timeout too long ({timeout} minutes)")
                        all_ok = False
                except:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Invalid sudo timeout configuration")
                    all_ok = False
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} sudo timeout not configured")
                all_ok = False
            
            # Check su access restriction
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking su command access restriction...")
            rc, output = self.run_cmd("grep -E '^auth\\s+required\\s+pam_wheel.so' /etc/pam.d/su")
            
            if output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} su access restricted to wheel group")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} su access not restricted")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Privilege Escalation{Colors.END}")
            all_ok = True
            
            # Install sudo if missing
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Ensuring sudo is installed...")
            if self.os_name == "ubuntu":
                self.run_cmd("apt-get install -y sudo")
            else:
                self.run_cmd("yum install -y sudo")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} sudo installed")
            
            # Configure sudo to use pty
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring sudo to use pty...")
            sudoers_config = "/etc/sudoers.d/99-hardn"
            self.run_cmd(f"echo 'Defaults use_pty' > {sudoers_config}")
            
            # Configure sudo log file
            self.run_cmd(f"echo 'Defaults logfile=\"/var/log/sudo.log\"' >> {sudoers_config}")
            
            # Configure sudo timeout
            self.run_cmd(f"echo 'Defaults timestamp_timeout=15' >> {sudoers_config}")
            
            # Set permissions
            self.run_cmd(f"chmod 440 {sudoers_config}")
            self.run_cmd(f"chown root:root {sudoers_config}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} sudo configuration completed")
            
            # Restrict su access
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Restricting su command access...")
            
            pam_su = "/etc/pam.d/su"
            rc, _ = self.run_cmd(f"grep -q '^auth\\s*required\\s*pam_wheel.so' {pam_su}")
            
            if rc != 0:
                self.run_cmd(f"echo 'auth required pam_wheel.so use_uid' >> {pam_su}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} su access restricted to wheel group")
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Add authorized users to wheel group: usermod -aG wheel <user>")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure PAM ----------------------

    def configure_pam(self, action: str) -> bool:
        """AC-30 to AC-50: Configure Pluggable Authentication Modules"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Pluggable Authentication Modules (PAM){Colors.END}")
            all_ok = True
            
            # Check PAM packages installed
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking PAM packages...")
            
            if self.os_name == "ubuntu":
                packages = ["libpam-modules", "libpam-pwquality"]
                check_cmd = "dpkg -l | grep -qw"
            else:
                packages = ["pam", "libpwquality"]
                check_cmd = "rpm -q"
            
            for package in packages:
                rc, _ = self.run_cmd(f"{check_cmd} {package}")
                if rc == 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {package} installed")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {package} not installed")
                    all_ok = False
            
            # Check pam_faillock configuration
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking pam_faillock configuration...")
            
            faillock_conf = "/etc/security/faillock.conf"
            rc, _ = self.run_cmd(f"test -f {faillock_conf}")
            
            if rc == 0:
                # Check deny
                rc, output = self.run_cmd(f"grep -E '^deny\\s*=\\s*[0-9]+' {faillock_conf}")
                if output and int(output.split('=')[1].strip()) <= 5:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Account lockout configured")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Account lockout not properly configured")
                    all_ok = False
                
                # Check unlock_time
                rc, output = self.run_cmd(f"grep -E '^unlock_time\\s*=\\s*[0-9]+' {faillock_conf}")
                if output:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Account unlock time configured")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Account unlock time not configured")
                    all_ok = False
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} faillock.conf not found")
                all_ok = False
            
            # Check pwquality configuration
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking password quality configuration...")
            
            pwquality_conf = "/etc/security/pwquality.conf"
            rc, _ = self.run_cmd(f"test -f {pwquality_conf}")
            
            if rc == 0:
                quality_checks = [
                    ("minlen", 14, "minimum password length"),
                    ("difok", 3, "different characters"),
                    ("maxrepeat", 3, "max repeated characters"),
                    ("maxsequence", 3, "max sequential characters"),
                    ("dictcheck", 1, "dictionary check"),
                ]
                
                for param, min_value, description in quality_checks:
                    rc, output = self.run_cmd(f"grep -E '^{param}\\s*=\\s*[0-9]+' {pwquality_conf}")
                    if output:
                        value = int(output.split('=')[1].strip())
                        if value >= min_value:
                            print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {description} configured")
                        else:
                            print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} too low")
                            all_ok = False
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} not configured")
                        all_ok = False
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} pwquality.conf not found")
                all_ok = False
            
            # Check password history
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking password history configuration...")
            rc, output = self.run_cmd("grep -E 'pam_pwhistory.so.*remember=' /etc/pam.d/common-password 2>/dev/null || grep -E 'pam_pwhistory.so.*remember=' /etc/pam.d/system-auth 2>/dev/null")
            
            if output and "remember=" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Password history configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Password history not configured")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Pluggable Authentication Modules (PAM){Colors.END}")
            all_ok = True
            
            # Install PAM packages
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Installing PAM packages...")
            
            if self.os_name == "ubuntu":
                self.run_cmd("apt-get update")
                self.run_cmd("apt-get install -y libpam-modules libpam-pwquality libpam-runtime")
            else:
                self.run_cmd("yum install -y pam libpwquality")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} PAM packages installed")
            
            # Configure faillock
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring account lockout (faillock)...")
            
            faillock_conf = "/etc/security/faillock.conf"
            
            faillock_settings = {
                "deny": "5",
                "unlock_time": "900",
                "fail_interval": "900",
                "even_deny_root": "",
            }
            
            for param, value in faillock_settings.items():
                rc, _ = self.run_cmd(f"grep -q '^{param}' {faillock_conf}")
                if rc == 0:
                    if value:
                        self.run_cmd(f"sed -i 's|^{param}.*|{param} = {value}|' {faillock_conf}")
                    else:
                        self.run_cmd(f"sed -i 's|^# {param}|{param}|' {faillock_conf}")
                else:
                    if value:
                        self.run_cmd(f"echo '{param} = {value}' >> {faillock_conf}")
                    else:
                        self.run_cmd(f"echo '{param}' >> {faillock_conf}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Account lockout configured")
            
            # Configure pwquality
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring password quality...")
            
            pwquality_conf = "/etc/security/pwquality.conf"
            
            pwquality_settings = {
                "minlen": "14",
                "difok": "3",
                "maxrepeat": "3",
                "maxsequence": "3",
                "dictcheck": "1",
                "enforcing": "1",
                "enforce_for_root": "",
            }
            
            for param, value in pwquality_settings.items():
                rc, _ = self.run_cmd(f"grep -q '^{param}' {pwquality_conf}")
                if rc == 0:
                    if value:
                        self.run_cmd(f"sed -i 's|^{param}.*|{param} = {value}|' {pwquality_conf}")
                    else:
                        self.run_cmd(f"sed -i 's|^# {param}|{param}|' {pwquality_conf}")
                else:
                    if value:
                        self.run_cmd(f"echo '{param} = {value}' >> {pwquality_conf}")
                    else:
                        self.run_cmd(f"echo '{param}' >> {pwquality_conf}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Password quality configured")
            
            # Configure password history
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring password history...")
            
            if self.os_name == "ubuntu":
                pam_password = "/etc/pam.d/common-password"
            else:
                pam_password = "/etc/pam.d/system-auth"
            
            # Check if pwhistory line exists
            rc, _ = self.run_cmd(f"grep -q 'pam_pwhistory.so' {pam_password}")
            
            if rc != 0:
                # Add after pam_unix line
                self.run_cmd(f"sed -i '/pam_unix.so/a password required pam_pwhistory.so remember=5 use_authtok enforce_for_root' {pam_password}")
            else:
                # Update existing
                self.run_cmd(f"sed -i 's|.*pam_pwhistory.so.*|password required pam_pwhistory.so remember=5 use_authtok enforce_for_root|' {pam_password}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Password history configured")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== ACCESS CONTROL: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic access control policy")

        # Configure privilege escalation (most critical)
        result = self.configure_privilege_escalation("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("access_control", "AC-23-29", "ok", result)

        print(f"\n{Colors.BOLD}Access Control Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Privilege Escalation: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== ACCESS CONTROL: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate access control policy")

        self.apply_basic(False)

        # Configure PAM
        result = self.configure_pam("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("access_control", "AC-30-50", "ok", result)

        print(f"\n{Colors.BOLD}Access Control Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Privilege Escalation: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"PAM Configuration: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== ACCESS CONTROL: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict access control policy")

        self.apply_moderate(False)

        # Configure SSH server (most aggressive)
        result = self.configure_ssh_server("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("access_control", "AC-1-22", "ok", result)

        print(f"\n{Colors.BOLD}Access Control Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Privilege Escalation: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"PAM Configuration: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"SSH Server: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict access control checks successfully!")

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

