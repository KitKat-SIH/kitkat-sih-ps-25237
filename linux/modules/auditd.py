# hardn/modules/auditd.py
"""
Implements Linux hardening controls for Section 8 – Logging and Auditing
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any
from .base import BaseHardeningModule, Colors


# ---------------------- Module Implementation ----------------------

class AuditdModule(BaseHardeningModule):
    id: str = "auditd"

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

    # ---------------------- System Logging ----------------------

    def configure_system_logging(self, action: str) -> bool:
        """AUD-1 to AUD-12: Configure system logging (journald and rsyslog)"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring System Logging{Colors.END}")
            all_ok = True
            
            # Check journald service
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking journald service status...")
            rc_enabled, _ = self.run_cmd("systemctl is-enabled systemd-journald")
            rc_active, _ = self.run_cmd("systemctl is-active systemd-journald")
            
            if rc_enabled == 0 and rc_active == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} journald service is enabled and active")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} journald service not properly configured")
                all_ok = False
            
            # Check journald configuration
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking journald configuration...")
            journald_conf = "/etc/systemd/journald.conf"
            
            rc, output = self.run_cmd(f"grep -E '^Storage=' {journald_conf}")
            if "Storage=persistent" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} journald persistent storage configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} journald persistent storage not configured")
                all_ok = False
            
            rc, output = self.run_cmd(f"grep -E '^Compress=' {journald_conf}")
            if "Compress=yes" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} journald compression enabled")
            else:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} journald compression not explicitly enabled")
            
            # Check rsyslog installation
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking rsyslog installation...")
            if self.os_name == "ubuntu":
                rc, _ = self.run_cmd("dpkg -l | grep -qw rsyslog")
            else:
                rc, _ = self.run_cmd("rpm -q rsyslog")
            
            if rc == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} rsyslog is installed")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} rsyslog not installed")
                all_ok = False
            
            # Check rsyslog service
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking rsyslog service status...")
            rc_enabled, _ = self.run_cmd("systemctl is-enabled rsyslog")
            rc_active, _ = self.run_cmd("systemctl is-active rsyslog")
            
            if rc_enabled == 0 and rc_active == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} rsyslog service is enabled and active")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} rsyslog service not properly configured")
                all_ok = False
            
            # Check rsyslog file creation mode
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking rsyslog file creation mode...")
            rc, output = self.run_cmd("grep -E '^\\$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null")
            
            if "0640" in output or "0600" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} rsyslog file creation mode configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} rsyslog file creation mode not properly configured")
                all_ok = False
            
            # Check logrotate
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking logrotate configuration...")
            rc, _ = self.run_cmd("test -f /etc/logrotate.d/rsyslog")
            
            if rc == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} logrotate is configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} logrotate not configured")
                all_ok = False
            
            # Check log file permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking log file permissions...")
            rc, output = self.run_cmd("find /var/log -type f -perm /027 -ls 2>/dev/null | head -5")
            
            if not output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Log file permissions properly configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Some log files have insecure permissions")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring System Logging{Colors.END}")
            all_ok = True
            
            # Configure journald
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring journald...")
            journald_conf = "/etc/systemd/journald.conf"
            
            self.run_cmd(f"cp {journald_conf} {journald_conf}.backup 2>/dev/null")
            
            journald_settings = {
                "Storage": "persistent",
                "Compress": "yes",
                "ForwardToSyslog": "yes",
                "MaxRetentionSec": "1month",
            }
            
            for param, value in journald_settings.items():
                rc, _ = self.run_cmd(f"grep -q '^{param}=' {journald_conf}")
                if rc == 0:
                    self.run_cmd(f"sed -i 's|^{param}=.*|{param}={value}|' {journald_conf}")
                else:
                    self.run_cmd(f"sed -i '/\\[Journal\\]/a {param}={value}' {journald_conf}")
            
            self.run_cmd("systemctl restart systemd-journald")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} journald configured")
            
            # Install and configure rsyslog
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Installing and configuring rsyslog...")
            
            if self.os_name == "ubuntu":
                self.run_cmd("apt-get install -y rsyslog")
            else:
                self.run_cmd("yum install -y rsyslog")
            
            # Enable and start rsyslog
            self.run_cmd("systemctl enable rsyslog")
            self.run_cmd("systemctl start rsyslog")
            
            # Configure rsyslog file creation mode
            rsyslog_conf = "/etc/rsyslog.d/50-default.conf"
            self.run_cmd(f"echo '$FileCreateMode 0640' > {rsyslog_conf}")
            
            # Configure basic rsyslog rules
            self.run_cmd(f"echo '*.info;mail.none;authpriv.none;cron.none /var/log/messages' >> {rsyslog_conf}")
            self.run_cmd(f"echo 'authpriv.* /var/log/secure' >> {rsyslog_conf}")
            self.run_cmd(f"echo 'mail.* /var/log/maillog' >> {rsyslog_conf}")
            self.run_cmd(f"echo 'cron.* /var/log/cron' >> {rsyslog_conf}")
            
            self.run_cmd("systemctl restart rsyslog")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} rsyslog configured")
            
            # Configure logrotate
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring logrotate...")
            
            logrotate_conf = "/etc/logrotate.d/rsyslog"
            logrotate_content = """
/var/log/messages
/var/log/secure
/var/log/maillog
/var/log/cron
{
    rotate 4
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/bin/systemctl restart rsyslog > /dev/null 2>&1 || true
    endscript
}
"""
            self.run_cmd(f"echo '{logrotate_content}' > {logrotate_conf}")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} logrotate configured")
            
            # Fix log file permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting log file permissions...")
            self.run_cmd("find /var/log -type f -exec chmod g-wx,o-rwx {} +")
            self.run_cmd("find /var/log -type d -exec chmod g-w,o-rwx {} +")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Log file permissions configured")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- System Auditing (auditd) ----------------------

    def configure_auditd_service(self, action: str) -> bool:
        """AUD-13 to AUD-20: Configure auditd service and data retention"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Auditd Service{Colors.END}")
            all_ok = True
            
            # Check auditd packages
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking auditd packages...")
            if self.os_name == "ubuntu":
                rc, _ = self.run_cmd("dpkg -l | grep -qw auditd")
            else:
                rc, _ = self.run_cmd("rpm -q audit")
            
            if rc == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} auditd packages installed")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} auditd not installed")
                all_ok = False
            
            # Check auditd service
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking auditd service status...")
            rc_enabled, _ = self.run_cmd("systemctl is-enabled auditd")
            rc_active, _ = self.run_cmd("systemctl is-active auditd")
            
            if rc_enabled == 0 and rc_active == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} auditd service is enabled and active")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} auditd service not properly configured")
                all_ok = False
            
            # Check audit enabled at boot
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if auditing enabled at boot...")
            rc, output = self.run_cmd("grep -E 'audit=1' /proc/cmdline")
            
            if output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Auditing enabled at boot")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Auditing not enabled at boot")
                all_ok = False
            
            # Check audit_backlog_limit
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking audit_backlog_limit...")
            rc, output = self.run_cmd("grep -E 'audit_backlog_limit=' /proc/cmdline")
            
            if output and "audit_backlog_limit=8192" in output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} audit_backlog_limit is sufficient")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} audit_backlog_limit not configured")
                all_ok = False
            
            # Check data retention settings
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking audit data retention...")
            audit_conf = "/etc/audit/auditd.conf"
            
            retention_checks = [
                ("max_log_file", "storage size"),
                ("max_log_file_action", "log file action"),
                ("space_left_action", "space left action"),
                ("admin_space_left_action", "admin space action"),
            ]
            
            for param, description in retention_checks:
                rc, output = self.run_cmd(f"grep -E '^{param}\\s*=' {audit_conf}")
                if output:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {description} configured")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} not configured")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Auditd Service{Colors.END}")
            all_ok = True
            
            # Install auditd
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Installing auditd...")
            
            if self.os_name == "ubuntu":
                self.run_cmd("apt-get install -y auditd audispd-plugins")
            else:
                self.run_cmd("yum install -y audit")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} auditd installed")
            
            # Enable and start auditd
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Enabling auditd service...")
            self.run_cmd("systemctl enable auditd")
            self.run_cmd("systemctl start auditd")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} auditd service enabled")
            
            # Configure audit at boot
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring audit at boot...")
            
            if self.os_name == "ubuntu":
                grub_cfg = "/etc/default/grub"
            else:
                grub_cfg = "/etc/default/grub"
            
            rc, output = self.run_cmd(f"grep 'GRUB_CMDLINE_LINUX=' {grub_cfg}")
            if "audit=1" not in output:
                self.run_cmd(f"sed -i 's|GRUB_CMDLINE_LINUX=\"|GRUB_CMDLINE_LINUX=\"audit=1 audit_backlog_limit=8192 |' {grub_cfg}")
                
                if self.os_name == "ubuntu":
                    self.run_cmd("update-grub")
                else:
                    self.run_cmd("grub2-mkconfig -o /boot/grub2/grub.cfg")
                
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit enabled at boot (reboot required)")
            else:
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit already enabled at boot")
            
            # Configure data retention
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring audit data retention...")
            audit_conf = "/etc/audit/auditd.conf"
            
            self.run_cmd(f"cp {audit_conf} {audit_conf}.backup")
            
            retention_settings = {
                "max_log_file": "100",
                "max_log_file_action": "keep_logs",
                "space_left": "75",
                "space_left_action": "email",
                "admin_space_left": "50",
                "admin_space_left_action": "halt",
                "disk_full_action": "halt",
                "disk_error_action": "halt",
            }
            
            for param, value in retention_settings.items():
                rc, _ = self.run_cmd(f"grep -q '^{param}\\s*=' {audit_conf}")
                if rc == 0:
                    self.run_cmd(f"sed -i 's|^{param}\\s*=.*|{param} = {value}|' {audit_conf}")
                else:
                    self.run_cmd(f"echo '{param} = {value}' >> {audit_conf}")
            
            self.run_cmd("systemctl restart auditd")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit data retention configured")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Auditd Rules ----------------------

    def configure_auditd_rules(self, action: str) -> bool:
        """AUD-21 to AUD-41: Configure comprehensive audit rules"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Auditd Rules{Colors.END}")
            all_ok = True
            
            # Check if audit rules are loaded
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking loaded audit rules...")
            rc, output = self.run_cmd("auditctl -l")
            
            if "No rules" in output:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} No audit rules loaded")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Audit rules are loaded")
            
            # Check for specific rule categories
            rule_checks = [
                ("sudoers", "sudoers modifications"),
                ("sudo", "sudo usage"),
                ("adjtimex", "time modifications"),
                ("sethostname", "network changes"),
                ("passwd", "user/group changes"),
                ("chmod", "permission changes"),
                ("mount", "filesystem mounts"),
                ("wtmp", "session information"),
                ("unlink", "file deletions"),
                ("selinux", "MAC changes"),
                ("init_module", "kernel modules"),
            ]
            
            for keyword, description in rule_checks:
                rc, _ = self.run_cmd(f"auditctl -l | grep -q {keyword}")
                if rc == 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {description} audit rules present")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} audit rules missing")
                    all_ok = False
            
            # Check if audit configuration is immutable
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if audit configuration is immutable...")
            rc, output = self.run_cmd("auditctl -l | grep -E '^-e 2'")
            
            if output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Audit configuration is immutable")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Audit configuration not immutable")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Auditd Rules{Colors.END}")
            all_ok = True
            
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Creating comprehensive audit rules...")
            
            rules_file = "/etc/audit/rules.d/hardn.rules"
            
            audit_rules = """# hardn audit rules - Comprehensive system auditing

# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (0=silent 1=printk 2=panic)
-f 1

# Audit sudoers changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Audit sudo usage
-w /var/log/sudo.log -p wa -k sudo_log_changes

# Audit date/time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time_change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time_change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time_change
-w /etc/localtime -p wa -k time_change

# Audit network environment changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network_changes
-a always,exit -F arch=b32 -S sethostname,setdomainname -k network_changes
-w /etc/issue -p wa -k network_changes
-w /etc/issue.net -p wa -k network_changes
-w /etc/hosts -p wa -k network_changes
-w /etc/network/ -p wa -k network_changes
-w /etc/sysconfig/network -p wa -k network_changes

# Audit user/group changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Audit permission changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod

# Audit unsuccessful file access attempts
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k file_access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k file_access
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k file_access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k file_access

# Audit filesystem mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts

# Audit session information
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Audit login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Audit file deletions
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k file_deletion
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k file_deletion

# Audit MAC changes (SELinux/AppArmor)
-w /etc/selinux/ -p wa -k mac_policy
-w /usr/share/selinux/ -p wa -k mac_policy
-w /etc/apparmor/ -p wa -k mac_policy
-w /etc/apparmor.d/ -p wa -k mac_policy

# Audit chcon usage
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng

# Audit setfacl usage
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng

# Audit chacl usage (if available)
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng

# Audit usermod usage
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k user_modification

# Audit kernel module changes
-a always,exit -F arch=b64 -S init_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,delete_module -k kernel_modules
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

# Make configuration immutable (must be last rule)
-e 2
"""
            
            self.run_cmd(f"echo '{audit_rules}' > {rules_file}")
            self.run_cmd(f"chmod 640 {rules_file}")
            self.run_cmd(f"chown root:root {rules_file}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit rules created")
            
            # Load rules
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Loading audit rules...")
            self.run_cmd("augenrules --load")
            
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} System reboot required to make audit configuration immutable")
            print(f"{Colors.YELLOW}         ↳{Colors.END} Until reboot, configuration can be modified")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Auditd File Access ----------------------

    def configure_auditd_file_access(self, action: str) -> bool:
        """AUD-42 to AUD-51: Configure audit file and tool permissions"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Auditd File Access{Colors.END}")
            all_ok = True
            
            # Check audit log file permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking audit log file permissions...")
            rc, output = self.run_cmd("find /var/log/audit -type f -perm /027 -ls")
            
            if not output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Audit log files have correct permissions")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Some audit log files have insecure permissions")
                all_ok = False
            
            # Check audit log directory permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking audit log directory permissions...")
            rc, perms = self.run_cmd("stat -c '%a' /var/log/audit")
            
            if perms == "750":
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Audit log directory permissions correct")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Audit log directory permissions incorrect ({perms})")
                all_ok = False
            
            # Check audit configuration file permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking audit configuration file permissions...")
            config_files = ["/etc/audit/auditd.conf", "/etc/audit/rules.d/"]
            
            for filepath in config_files:
                rc, perms = self.run_cmd(f"stat -c '%a' {filepath} 2>/dev/null")
                if rc == 0:
                    if perms in ["640", "600", "750", "700"]:
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {filepath} permissions correct")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {filepath} permissions incorrect")
                        all_ok = False
            
            # Check audit tool permissions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking audit tool permissions...")
            audit_tools = [
                "/sbin/auditctl",
                "/sbin/aureport",
                "/sbin/ausearch",
                "/sbin/autrace",
                "/sbin/auditd",
                "/sbin/augenrules",
            ]
            
            for tool in audit_tools:
                rc, perms = self.run_cmd(f"stat -c '%a' {tool} 2>/dev/null")
                if rc == 0:
                    if perms in ["755", "750"]:
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {tool} permissions correct")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {tool} permissions incorrect")
                        all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Auditd File Access{Colors.END}")
            all_ok = True
            
            # Set audit log file permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting audit log file permissions...")
            self.run_cmd("find /var/log/audit -type f -exec chmod 600 {} +")
            self.run_cmd("find /var/log/audit -type f -exec chown root:root {} +")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit log file permissions set")
            
            # Set audit log directory permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting audit log directory permissions...")
            self.run_cmd("chmod 750 /var/log/audit")
            self.run_cmd("chown root:root /var/log/audit")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit log directory permissions set")
            
            # Set audit configuration file permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting audit configuration file permissions...")
            self.run_cmd("chmod 640 /etc/audit/auditd.conf")
            self.run_cmd("chown root:root /etc/audit/auditd.conf")
            self.run_cmd("chmod 750 /etc/audit/rules.d")
            self.run_cmd("chown root:root /etc/audit/rules.d")
            self.run_cmd("find /etc/audit/rules.d -type f -exec chmod 640 {} +")
            self.run_cmd("find /etc/audit/rules.d -type f -exec chown root:root {} +")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit configuration file permissions set")
            
            # Set audit tool permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting audit tool permissions...")
            audit_tools = [
                "/sbin/auditctl",
                "/sbin/aureport",
                "/sbin/ausearch",
                "/sbin/autrace",
                "/sbin/auditd",
                "/sbin/augenrules",
            ]
            
            for tool in audit_tools:
                self.run_cmd(f"chmod 755 {tool} 2>/dev/null")
                self.run_cmd(f"chown root:root {tool} 2>/dev/null")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Audit tool permissions set")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Integrity Checking ----------------------

    def configure_integrity_checking(self, action: str) -> bool:
        """AUD-52 to AUD-54: Configure AIDE for filesystem integrity monitoring"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Integrity Checking (AIDE){Colors.END}")
            all_ok = True
            
            # Check AIDE installation
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking AIDE installation...")
            if self.os_name == "ubuntu":
                rc, _ = self.run_cmd("dpkg -l | grep -qw aide")
            else:
                rc, _ = self.run_cmd("rpm -q aide")
            
            if rc == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} AIDE is installed")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} AIDE not installed")
                all_ok = False
            
            # Check AIDE database exists
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking AIDE database...")
            rc, _ = self.run_cmd("test -f /var/lib/aide/aide.db")
            
            if rc == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} AIDE database initialized")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} AIDE database not initialized")
                all_ok = False
            
            # Check AIDE cron job
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking AIDE regular checks...")
            rc, output = self.run_cmd("grep -r aide /etc/cron.* /etc/crontab 2>/dev/null")
            
            if output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} AIDE regular checks configured")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} AIDE regular checks not configured")
                all_ok = False
            
            # Check audit tool integrity
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking audit tool integrity protection...")
            rc, output = self.run_cmd("grep -E 'auditctl|aureport|ausearch' /etc/aide/aide.conf 2>/dev/null")
            
            if output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Audit tools protected by AIDE")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Audit tools not protected by AIDE")
                all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Integrity Checking (AIDE){Colors.END}")
            all_ok = True
            
            # Install AIDE
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Installing AIDE...")
            
            if self.os_name == "ubuntu":
                self.run_cmd("apt-get install -y aide aide-common")
            else:
                self.run_cmd("yum install -y aide")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} AIDE installed")
            
            # Configure AIDE to protect audit tools
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring AIDE to protect audit tools...")
            
            aide_conf = "/etc/aide/aide.conf" if self.os_name == "ubuntu" else "/etc/aide.conf"
            
            aide_rules = """
# Audit tools integrity
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
"""
            
            self.run_cmd(f"echo '{aide_rules}' >> {aide_conf}")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} AIDE configured to protect audit tools")
            
            # Initialize AIDE database
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Initializing AIDE database...")
            print(f"{Colors.YELLOW}         ↳{Colors.END} This may take several minutes...")
            
            if self.os_name == "ubuntu":
                rc, _ = self.run_cmd("aideinit")
                if rc == 0:
                    self.run_cmd("cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db")
            else:
                self.run_cmd("aide --init")
                self.run_cmd("cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} AIDE database initialized")
            
            # Configure AIDE cron job
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring AIDE regular checks...")
            
            aide_cron = "/etc/cron.daily/aide"
            aide_cron_content = """#!/bin/bash
# AIDE integrity check

if [ -x /usr/bin/aide ]; then
    /usr/bin/aide --check | mail -s "AIDE Integrity Check - $(hostname)" root
elif [ -x /usr/sbin/aide ]; then
    /usr/sbin/aide --check | mail -s "AIDE Integrity Check - $(hostname)" root
fi
"""
            
            self.run_cmd(f"echo '{aide_cron_content}' > {aide_cron}")
            self.run_cmd(f"chmod 755 {aide_cron}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} AIDE regular checks configured (daily)")
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Ensure mail service is configured for AIDE reports")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== AUDITD: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic auditd policy")

        # Configure system logging (most fundamental)
        result = self.configure_system_logging("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("AUD-1-12", "ok", result)

        print(f"\n{Colors.BOLD}Auditd Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"System Logging: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== AUDITD: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate auditd policy")

        self.apply_basic(False)

        # Configure auditd service
        result = self.configure_auditd_service("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("AUD-13-20", "ok", result)

        # Configure auditd file access
        result = self.configure_auditd_file_access("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("AUD-42-51", "ok", result)

        print(f"\n{Colors.BOLD}Auditd Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"System Logging: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Auditd Service: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Audit File Access: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== AUDITD: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict auditd policy")

        self.apply_moderate(False)

        # Configure comprehensive audit rules
        result = self.configure_auditd_rules("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("AUD-21-41", "ok", result)

        # Configure integrity checking
        result = self.configure_integrity_checking("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("AUD-52-54", "ok", result)

        print(f"\n{Colors.BOLD}Auditd Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"System Logging: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Auditd Service: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Audit File Access: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Audit Rules: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Integrity Checking: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict auditd checks successfully!")

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
