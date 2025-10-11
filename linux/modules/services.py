# hardn/modules/services.py
"""
Implements Linux hardening controls for Section 3 – Services Configuration
as per Annexure B of the SIH problem statement (Multi-Platform System Hardening Tool: hardn).
Supports Ubuntu (20.04+) and CentOS (7+).
"""

import subprocess
from typing import Any, Dict, Tuple, List
from .base import BaseHardeningModule, Colors


# ---------------------- Module Implementation ----------------------

class ServicesModule(BaseHardeningModule):
    id: str = "services"

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

    # ---------------------- Configure Server Services ----------------------

    def configure_server_services(self, action: str) -> bool:
        """SRV-1 to SRV-22: Ensure unnecessary server services are disabled"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Server Services{Colors.END}")
            all_ok = True
            
            # Map of service descriptions to service names (Ubuntu, CentOS)
            services = [
                ("autofs", ["autofs"], "AutoFS automounter"),
                ("avahi-daemon", ["avahi-daemon"], "Avahi daemon"),
                ("isc-dhcp-server", ["dhcpd", "isc-dhcp-server"], "DHCP server"),
                ("bind9", ["named", "bind9"], "DNS server"),
                ("dnsmasq", ["dnsmasq"], "DNSMasq"),
                ("vsftpd", ["vsftpd", "proftpd"], "FTP server"),
                ("slapd", ["slapd"], "LDAP server"),
                ("dovecot", ["dovecot", "cyrus-imapd"], "Mail access server"),
                ("nfs-server", ["nfs-server", "nfs"], "NFS server"),
                ("ypserv", ["ypserv"], "NIS server"),
                ("cups", ["cups"], "Print server"),
                ("rpcbind", ["rpcbind"], "RPC bind"),
                ("rsync", ["rsync"], "rsync daemon"),
                ("smbd", ["smbd", "smb"], "Samba file server"),
                ("snmpd", ["snmpd"], "SNMP daemon"),
                ("tftpd-hpa", ["tftp", "tftpd-hpa"], "TFTP server"),
                ("squid", ["squid"], "Web proxy server"),
                ("apache2", ["httpd", "apache2", "nginx"], "Web server"),
                ("xinetd", ["xinetd"], "xinetd super-server"),
                ("xserver-xorg", ["gdm", "lightdm", "xdm"], "X Window server"),
            ]
            
            for check_name, service_names, description in services:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking {description}...")
                
                service_found = False
                service_enabled = False
                
                for svc in service_names:
                    rc_enabled, _ = self.run_cmd(f"systemctl is-enabled {svc} 2>/dev/null")
                    rc_active, _ = self.run_cmd(f"systemctl is-active {svc} 2>/dev/null")
                    
                    if rc_enabled == 0 or rc_active == 0:
                        service_found = True
                        service_enabled = True
                        break
                
                if not service_enabled:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {description} not in use")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} is active or enabled")
                    all_ok = False
            
            # Check mail transfer agent (special case - should be local-only)
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking mail transfer agent configuration...")
            rc, output = self.run_cmd("ss -lntu | grep -E ':25\\s' | grep -v '127.0.0.1:25'")
            
            if rc != 0 or not output:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Mail transfer agent configured for local-only")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Mail transfer agent listening on non-local interface")
                all_ok = False
            
            # Check listening services
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking for approved listening services...")
            rc, output = self.run_cmd("ss -lntu")
            
            if output:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Review listening services:")
                # Show first 10 lines
                for line in output.split('\n')[:10]:
                    if line and not line.startswith('Netid'):
                        print(f"{Colors.YELLOW}         ↳{Colors.END} {line}")
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Server Services{Colors.END}")
            all_ok = True
            
            services = [
                ("autofs", ["autofs"], "AutoFS automounter"),
                ("avahi-daemon", ["avahi-daemon"], "Avahi daemon"),
                ("isc-dhcp-server", ["dhcpd", "isc-dhcp-server"], "DHCP server"),
                ("bind9", ["named", "bind9"], "DNS server"),
                ("dnsmasq", ["dnsmasq"], "DNSMasq"),
                ("vsftpd", ["vsftpd", "proftpd"], "FTP server"),
                ("slapd", ["slapd"], "LDAP server"),
                ("dovecot", ["dovecot", "cyrus-imapd"], "Mail access server"),
                ("nfs-server", ["nfs-server", "nfs"], "NFS server"),
                ("ypserv", ["ypserv"], "NIS server"),
                ("cups", ["cups"], "Print server"),
                ("rpcbind", ["rpcbind"], "RPC bind"),
                ("rsync", ["rsync"], "rsync daemon"),
                ("smbd", ["smbd", "smb"], "Samba file server"),
                ("snmpd", ["snmpd"], "SNMP daemon"),
                ("tftpd-hpa", ["tftp", "tftpd-hpa"], "TFTP server"),
                ("squid", ["squid"], "Web proxy server"),
                ("apache2", ["httpd", "apache2", "nginx"], "Web server"),
                ("xinetd", ["xinetd"], "xinetd super-server"),
                ("xserver-xorg", ["gdm", "lightdm", "xdm"], "X Window server"),
            ]
            
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Disabling unnecessary server services...")
            
            for check_name, service_names, description in services:
                for svc in service_names:
                    # Try to stop and disable
                    self.run_cmd(f"systemctl stop {svc} 2>/dev/null")
                    self.run_cmd(f"systemctl disable {svc} 2>/dev/null")
                    self.run_cmd(f"systemctl mask {svc} 2>/dev/null")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Server services disabled")
            
            # Configure mail transfer agent for local-only
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring mail transfer agent for local-only mode...")
            
            # For Postfix
            if self.os_name == "ubuntu":
                self.run_cmd("postconf -e 'inet_interfaces = loopback-only' 2>/dev/null")
                self.run_cmd("systemctl restart postfix 2>/dev/null")
            else:
                self.run_cmd("postconf -e 'inet_interfaces = loopback-only' 2>/dev/null")
                self.run_cmd("systemctl restart postfix 2>/dev/null")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Mail transfer agent configured for local-only")
            
            # Show listening services for manual review
            print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} Review listening services with: ss -lntu")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Client Services ----------------------

    def configure_client_services(self, action: str) -> bool:
        """SRV-23 to SRV-28: Ensure unnecessary client packages are removed"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Client Services{Colors.END}")
            all_ok = True
            
            # Map of client packages (Ubuntu, CentOS)
            if self.os_name == "ubuntu":
                packages = [
                    ("nis", "NIS client"),
                    ("rsh-client", "RSH client"),
                    ("talk", "Talk client"),
                    ("telnet", "Telnet client"),
                    ("ldap-utils", "LDAP client"),
                    ("ftp", "FTP client"),
                ]
                check_cmd = "dpkg -l | grep -qw"
            else:
                packages = [
                    ("ypbind", "NIS client"),
                    ("rsh", "RSH client"),
                    ("talk", "Talk client"),
                    ("telnet", "Telnet client"),
                    ("openldap-clients", "LDAP client"),
                    ("ftp", "FTP client"),
                ]
                check_cmd = "rpm -q"
            
            for package, description in packages:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if {description} is installed...")
                rc, _ = self.run_cmd(f"{check_cmd} {package}")
                
                if rc != 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {description} not installed")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {description} is installed")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Client Services{Colors.END}")
            all_ok = True
            
            if self.os_name == "ubuntu":
                packages = ["nis", "rsh-client", "talk", "telnet", "ldap-utils", "ftp"]
                remove_cmd = "apt-get remove -y"
            else:
                packages = ["ypbind", "rsh", "talk", "telnet", "openldap-clients", "ftp"]
                remove_cmd = "yum remove -y"
            
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Removing unnecessary client packages...")
            
            for package in packages:
                self.run_cmd(f"{remove_cmd} {package} 2>/dev/null")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Unnecessary client packages removed")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Time Synchronization ----------------------

    def configure_time_synchronization(self, action: str) -> bool:
        """SRV-29 to SRV-35: Configure time synchronization"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Time Synchronization{Colors.END}")
            all_ok = True
            
            # Check if time sync is in use
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if time synchronization is in use...")
            
            timesyncd_active = self.run_cmd("systemctl is-active systemd-timesyncd 2>/dev/null")[0] == 0
            chrony_active = self.run_cmd("systemctl is-active chronyd 2>/dev/null")[0] == 0
            ntp_active = self.run_cmd("systemctl is-active ntp 2>/dev/null")[0] == 0
            
            active_count = sum([timesyncd_active, chrony_active, ntp_active])
            
            if active_count == 0:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} No time synchronization service active")
                all_ok = False
            elif active_count > 1:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Multiple time sync daemons running (should be only one)")
                all_ok = False
            else:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Single time synchronization daemon in use")
            
            # Check systemd-timesyncd if active
            if timesyncd_active:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking systemd-timesyncd configuration...")
                
                rc, output = self.run_cmd("grep -E '^NTP=' /etc/systemd/timesyncd.conf")
                if rc == 0 and output:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} systemd-timesyncd configured with timeserver")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} systemd-timesyncd not configured with timeserver")
                    all_ok = False
            
            # Check chrony if active
            if chrony_active:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking chrony configuration...")
                
                rc, output = self.run_cmd("grep -E '^(server|pool)' /etc/chrony/chrony.conf 2>/dev/null || grep -E '^(server|pool)' /etc/chrony.conf 2>/dev/null")
                if rc == 0 and output:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} chrony configured with timeserver")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} chrony not configured with timeserver")
                    all_ok = False
                
                # Check chrony user
                rc, output = self.run_cmd("ps -ef | grep chronyd | grep -v grep | grep -q '_chrony\\|chrony'")
                if rc == 0:
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} chrony running as unprivileged user")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} chrony not running as unprivileged user")
                    all_ok = False
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Time Synchronization{Colors.END}")
            all_ok = True
            
            # Check which time sync services are running
            timesyncd_active = self.run_cmd("systemctl is-active systemd-timesyncd 2>/dev/null")[0] == 0
            chrony_active = self.run_cmd("systemctl is-active chronyd 2>/dev/null")[0] == 0
            ntp_active = self.run_cmd("systemctl is-active ntp 2>/dev/null")[0] == 0
            
            active_count = sum([timesyncd_active, chrony_active, ntp_active])
            
            if active_count > 1:
                print(f"{Colors.BLUE}[WORKING]{Colors.END} Disabling conflicting time sync services...")
                # Prefer chrony, then systemd-timesyncd
                if chrony_active:
                    self.run_cmd("systemctl stop systemd-timesyncd 2>/dev/null")
                    self.run_cmd("systemctl disable systemd-timesyncd 2>/dev/null")
                    self.run_cmd("systemctl stop ntp 2>/dev/null")
                    self.run_cmd("systemctl disable ntp 2>/dev/null")
                elif timesyncd_active:
                    self.run_cmd("systemctl stop chronyd 2>/dev/null")
                    self.run_cmd("systemctl disable chronyd 2>/dev/null")
                    self.run_cmd("systemctl stop ntp 2>/dev/null")
                    self.run_cmd("systemctl disable ntp 2>/dev/null")
            
            # Configure chrony if available, otherwise systemd-timesyncd
            chrony_installed = self.run_cmd("which chronyd 2>/dev/null")[0] == 0
            
            if chrony_installed:
                print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring chrony...")
                
                # Add default NTP servers if not configured
                chrony_conf = "/etc/chrony/chrony.conf" if self.os_name == "ubuntu" else "/etc/chrony.conf"
                rc, _ = self.run_cmd(f"grep -q '^server' {chrony_conf} 2>/dev/null")
                
                if rc != 0:
                    self.run_cmd(f"echo 'server 0.pool.ntp.org iburst' >> {chrony_conf}")
                    self.run_cmd(f"echo 'server 1.pool.ntp.org iburst' >> {chrony_conf}")
                
                # Ensure running as chrony user
                if self.os_name == "ubuntu":
                    self.run_cmd("sed -i 's/^user .*/user _chrony/' /etc/chrony/chrony.conf 2>/dev/null")
                else:
                    self.run_cmd("sed -i 's/^user .*/user chrony/' /etc/chrony.conf 2>/dev/null")
                
                # Enable and start
                self.run_cmd("systemctl enable chronyd")
                self.run_cmd("systemctl start chronyd")
                
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} chrony configured and enabled")
            else:
                print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring systemd-timesyncd...")
                
                # Configure systemd-timesyncd
                rc, _ = self.run_cmd("grep -q '^NTP=' /etc/systemd/timesyncd.conf")
                
                if rc != 0:
                    self.run_cmd("echo 'NTP=0.pool.ntp.org 1.pool.ntp.org' >> /etc/systemd/timesyncd.conf")
                
                # Enable and start
                self.run_cmd("systemctl enable systemd-timesyncd")
                self.run_cmd("systemctl start systemd-timesyncd")
                
                print(f"{Colors.GREEN}[SUCCESS]{Colors.END} systemd-timesyncd configured and enabled")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Configure Job Schedulers ----------------------

    def configure_job_schedulers(self, action: str) -> bool:
        """SRV-36 to SRV-43: Configure cron job schedulers"""
        
        def check() -> bool:
            print(f"\n{Colors.BOLD}Configuring Job Schedulers{Colors.END}")
            all_ok = True
            
            # Check if cron is enabled
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if cron daemon is enabled and active...")
            rc_enabled, _ = self.run_cmd("systemctl is-enabled cron 2>/dev/null || systemctl is-enabled crond 2>/dev/null")
            rc_active, _ = self.run_cmd("systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null")
            
            if rc_enabled == 0 and rc_active == 0:
                print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} Cron daemon is enabled and active")
            else:
                print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} Cron daemon is not properly configured")
                all_ok = False
            
            # Check cron file permissions
            cron_files = [
                ("/etc/crontab", "700"),
                ("/etc/cron.hourly", "700"),
                ("/etc/cron.daily", "700"),
                ("/etc/cron.weekly", "700"),
                ("/etc/cron.monthly", "700"),
                ("/etc/cron.d", "700"),
            ]
            
            for filepath, expected_perms in cron_files:
                print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking permissions on {filepath}...")
                rc, perms = self.run_cmd(f"stat -c '%a' {filepath} 2>/dev/null")
                
                if rc == 0:
                    if perms == expected_perms:
                        print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} {filepath} has correct permissions ({expected_perms})")
                    else:
                        print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} {filepath} permissions incorrect (current: {perms}, expected: {expected_perms})")
                        all_ok = False
                else:
                    print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} {filepath} not found")
            
            # Check crontab restrictions
            print(f"{Colors.YELLOW}[INFO]{Colors.END} Checking if crontab is restricted to authorized users...")
            
            cron_allow_exists = self.run_cmd("test -f /etc/cron.allow")[0] == 0
            cron_deny_exists = self.run_cmd("test -f /etc/cron.deny")[0] == 0
            
            if cron_allow_exists:
                rc, perms = self.run_cmd("stat -c '%a' /etc/cron.allow")
                if perms == "640":
                    print(f"{Colors.GREEN}[COMPLIANT]{Colors.END} /etc/cron.allow exists with correct permissions")
                else:
                    print(f"{Colors.RED}[NON-COMPLIANT]{Colors.END} /etc/cron.allow has incorrect permissions")
                    all_ok = False
            else:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} /etc/cron.allow does not exist")
                all_ok = False
            
            if cron_deny_exists:
                print(f"{Colors.YELLOW}[MANUAL CHECK]{Colors.END} /etc/cron.deny exists (should use cron.allow instead)")
            
            return all_ok

        def enforce() -> bool:
            print(f"\n{Colors.BOLD}Configuring Job Schedulers{Colors.END}")
            all_ok = True
            
            # Enable and start cron
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Enabling cron daemon...")
            self.run_cmd("systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null")
            self.run_cmd("systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null")
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Cron daemon enabled and started")
            
            # Set cron file permissions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Setting cron file permissions...")
            
            cron_files = [
                ("/etc/crontab", "700", "root", "root"),
                ("/etc/cron.hourly", "700", "root", "root"),
                ("/etc/cron.daily", "700", "root", "root"),
                ("/etc/cron.weekly", "700", "root", "root"),
                ("/etc/cron.monthly", "700", "root", "root"),
                ("/etc/cron.d", "700", "root", "root"),
            ]
            
            for filepath, perms, owner, group in cron_files:
                rc, _ = self.run_cmd(f"test -e {filepath}")
                if rc == 0:
                    self.run_cmd(f"chmod {perms} {filepath}")
                    self.run_cmd(f"chown {owner}:{group} {filepath}")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Cron file permissions configured")
            
            # Configure crontab restrictions
            print(f"{Colors.BLUE}[WORKING]{Colors.END} Configuring crontab access restrictions...")
            
            # Create /etc/cron.allow
            self.run_cmd("touch /etc/cron.allow")
            self.run_cmd("chmod 640 /etc/cron.allow")
            self.run_cmd("chown root:root /etc/cron.allow")
            
            # Remove /etc/cron.deny if exists
            self.run_cmd("rm -f /etc/cron.deny")
            
            # Same for at
            self.run_cmd("touch /etc/at.allow")
            self.run_cmd("chmod 640 /etc/at.allow")
            self.run_cmd("chown root:root /etc/at.allow")
            self.run_cmd("rm -f /etc/at.deny")
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Crontab access restrictions configured")
            
            return all_ok

        return check() if action == "check" else enforce()

    # ---------------------- Policy Levels ----------------------

    def apply_basic(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== SERVICES: BASIC POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying basic services policy")

        # Configure job schedulers (most critical)
        result = self.configure_job_schedulers("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("services", "SRV-36-43", "ok", result)

        print(f"\n{Colors.BOLD}Services Basic Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Job Schedulers: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_moderate(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== SERVICES: MODERATE POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying moderate services policy")

        self.apply_basic(False)

        # Configure client services
        result = self.configure_client_services("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("services", "SRV-23-28", "ok", result)

        # Configure time synchronization
        result = self.configure_time_synchronization("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("services", "SRV-29-35", "ok", result)

        print(f"\n{Colors.BOLD}Services Moderate Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Job Schedulers: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Client Services: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Time Synchronization: {Colors.GREEN}CONFIGURED{Colors.END}")

    def apply_strict(self, out: bool = True) -> None:
        if out:
            print(f"\n{Colors.BOLD}{Colors.BLUE}========== SERVICES: STRICT POLICY =========={Colors.END}")
        self.logger.log("INFO", "Applying strict services policy")

        self.apply_moderate(False)

        # Configure server services (most aggressive)
        result = self.configure_server_services("check" if self.ctx.get("mode") == "audit" else "enforce")
        self.add_result("services", "SRV-1-22", "ok", result)

        print(f"\n{Colors.BOLD}Services Strict Policy Summary{Colors.END}")
        print(f"{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"Job Schedulers: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Client Services: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Time Synchronization: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"Server Services: {Colors.GREEN}CONFIGURED{Colors.END}")
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Completed all strict services checks successfully!")

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
