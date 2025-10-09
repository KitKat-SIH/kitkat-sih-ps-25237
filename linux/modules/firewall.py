"""
For i.:
- Check :-
Ubuntu: dpkg -l | grep -qw ufw
CentOS: rpm -q ufw
- Enforce:-
Ubuntu: apt-get install -y ufw
CentOS: yum install -y ufw

For ii.:
- Check :-
Ubuntu: dpkg -l | grep -qw iptables-persistent
CentOS: rpm -q iptables-services
- Enforce:-
Ubuntu: apt-get remove -y iptables-persistent
CentOS: yum remove -y iptables-services

For iii.:
- Check :-
Ubuntu: systemctl is-enabled ufw
CentOS: systemctl is-enabled ufw
- Enforce:-
Ubuntu: systemctl enable ufw && systemctl start ufw
CentOS: systemctl enable ufw && systemctl start ufw

For iv.:
- Check :-
Ubuntu: ufw status verbose | grep -q "Anywhere on lo"
CentOS: ufw status verbose | grep -q "Anywhere on lo"
- Enforce:-
Ubuntu: ufw allow in on lo && ufw reload
CentOS: ufw allow in on lo && ufw reload

For v.:
- Check :-
Ubuntu: ufw status verbose | grep -q "Default: deny (outgoing)"
CentOS: ufw status verbose | grep -q "Default: deny (outgoing)"
- Enforce:-
Ubuntu: ufw default deny outgoing && ufw reload
CentOS: ufw default deny outgoing && ufw reload

For vi.:
- Check :-
Ubuntu: ufw status numbered
CentOS: ufw status numbered
- Enforce:-
Ubuntu: <Manual: define and apply rules for all required open ports, e.g., ufw allow 22/tcp; ufw reload>
CentOS: <Manual: define and apply rules for all required open ports, e.g., ufw allow 22/tcp; ufw reload>

For vii.:
- Check :-
Ubuntu: ufw status verbose | grep -q "Default: deny (incoming)"
CentOS: ufw status verbose | grep -q "Default: deny (incoming)"
- Enforce:-
Ubuntu: ufw default deny incoming && ufw reload
CentOS: ufw default deny incoming && ufw reload

For viii.:
- Check :-
Ubuntu: systemctl is-active iptables
CentOS: systemctl is-active iptables
- Enforce:-
Ubuntu: systemctl stop iptables && systemctl disable iptables
CentOS: systemctl stop iptables && systemctl disable iptables

"""

from base import BaseHardeningModule

class FirewallModule(BaseHardeningModule):
    #TODO
