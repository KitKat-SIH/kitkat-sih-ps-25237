#!/usr/bin/env python3
"""
Test script to verify what Windows security fixes are actually working
Run this on Windows AFTER running masterfix.py to see what actually got fixed
"""
import subprocess
import sys
import os

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def test_password_complexity():
    """Test current password complexity status"""
    print(f"\n{Colors.BOLD}TESTING PASSWORD COMPLEXITY{Colors.END}")
    print("-" * 50)
    
    try:
        # Export current security policy
        result = subprocess.run([
            "secedit", "/export", "/cfg", "C:\\temp_test.inf"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            try:
                with open("C:\\temp_test.inf", 'r', encoding='utf-16') as f:
                    content = f.read()
                    
                if "PasswordComplexity = 1" in content:
                    print(f"{Colors.GREEN}✓ Password complexity is ENABLED{Colors.END}")
                    return True
                elif "PasswordComplexity = 0" in content:
                    print(f"{Colors.RED}✗ Password complexity is DISABLED{Colors.END}")
                    return False
                else:
                    print(f"{Colors.YELLOW}? Password complexity setting not found{Colors.END}")
                    return False
                    
            except Exception as e:
                print(f"{Colors.RED}Error reading policy file: {e}{Colors.END}")
                return False
            finally:
                try:
                    os.remove("C:\\temp_test.inf")
                except:
                    pass
        else:
            print(f"{Colors.RED}Failed to export security policy{Colors.END}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        return False

def test_audit_policies():
    """Test current audit policy status"""
    print(f"\n{Colors.BOLD}TESTING AUDIT POLICIES{Colors.END}")
    print("-" * 50)
    
    try:
        result = subprocess.run([
            "auditpol", "/get", "/category:*"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            output = result.stdout
            
            # Check key policies
            test_policies = [
                "Sensitive Privilege Use",
                "User Account Management", 
                "Security Group Management",
                "Process Creation"
            ]
            
            compliant = 0
            for policy in test_policies:
                if policy.lower() in output.lower():
                    # Find the line with this policy
                    for line in output.split('\n'):
                        if policy.lower() in line.lower():
                            if "success and failure" in line.lower():
                                print(f"{Colors.GREEN}✓ {policy}: Success and Failure{Colors.END}")
                                compliant += 1
                            elif "success" in line.lower():
                                print(f"{Colors.YELLOW}? {policy}: Success only{Colors.END}")
                                compliant += 0.5
                            elif "no auditing" in line.lower():
                                print(f"{Colors.RED}✗ {policy}: No Auditing{Colors.END}")
                            else:
                                print(f"{Colors.YELLOW}? {policy}: {line.strip()}{Colors.END}")
                            break
                else:
                    print(f"{Colors.RED}✗ {policy}: Not found{Colors.END}")
            
            return compliant >= len(test_policies) * 0.75
        else:
            print(f"{Colors.RED}Failed to get audit policies{Colors.END}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        return False

def test_firewall_rules():
    """Test current firewall rules"""
    print(f"\n{Colors.BOLD}TESTING FIREWALL RULES{Colors.END}")
    print("-" * 50)
    
    try:
        result = subprocess.run([
            "netsh", "advfirewall", "firewall", "show", "rule", "name=all"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            
            # Check for blocking rules on key ports
            test_ports = ["445", "137", "138", "139", "3389"]
            blocked_ports = 0
            
            for port in test_ports:
                port_blocked = False
                if f"localport={port}" in output or f"localport: {port}" in output:
                    # Check if there's a blocking rule for this port
                    lines = output.split('\n')
                    for i, line in enumerate(lines):
                        if f"localport={port}" in line or f"localport: {port}" in line:
                            # Check surrounding lines for block action
                            for j in range(max(0, i-5), min(len(lines), i+6)):
                                if "action=block" in lines[j] or "action: block" in lines[j]:
                                    port_blocked = True
                                    break
                            if port_blocked:
                                break
                
                if port_blocked:
                    print(f"{Colors.GREEN}✓ Port {port} is blocked{Colors.END}")
                    blocked_ports += 1
                else:
                    print(f"{Colors.RED}✗ Port {port} is not blocked{Colors.END}")
            
            return blocked_ports >= 3  # At least 3 ports should be blocked
        else:
            print(f"{Colors.RED}Failed to get firewall rules{Colors.END}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        return False

def test_user_rights():
    """Test current user rights assignments"""
    print(f"\n{Colors.BOLD}TESTING USER RIGHTS{Colors.END}")
    print("-" * 50)
    
    try:
        # Export current security policy
        result = subprocess.run([
            "secedit", "/export", "/cfg", "C:\\temp_rights_test.inf"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            try:
                with open("C:\\temp_rights_test.inf", 'r', encoding='utf-16') as f:
                    content = f.read()
                
                # Check if Guest is in SeInteractiveLogonRight
                guest_in_logon = False
                if "SeInteractiveLogonRight" in content:
                    for line in content.split('\n'):
                        if "SeInteractiveLogonRight" in line and "Guest" in line:
                            guest_in_logon = True
                            break
                
                if guest_in_logon:
                    print(f"{Colors.RED}✗ Guest account can log on locally{Colors.END}")
                    return False
                else:
                    print(f"{Colors.GREEN}✓ Guest account cannot log on locally{Colors.END}")
                    return True
                    
            except Exception as e:
                print(f"{Colors.RED}Error reading policy file: {e}{Colors.END}")
                return False
            finally:
                try:
                    os.remove("C:\\temp_rights_test.inf")
                except:
                    pass
        else:
            print(f"{Colors.RED}Failed to export security policy{Colors.END}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        return False

def main():
    print(f"{Colors.BOLD}WINDOWS SECURITY FIXES TEST{Colors.END}")
    print("=" * 60)
    print("This script tests if the security fixes from masterfix.py actually worked")
    print("Run this AFTER running masterfix.py")
    print()
    
    # Run all tests
    tests = [
        ("Password Complexity", test_password_complexity),
        ("Audit Policies", test_audit_policies),
        ("Firewall Rules", test_firewall_rules),
        ("User Rights", test_user_rights)
    ]
    
    results = {}
    for test_name, test_func in tests:
        results[test_name] = test_func()
    
    # Summary
    print(f"\n{Colors.BOLD}TEST RESULTS SUMMARY{Colors.END}")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results.items():
        status = f"{Colors.GREEN}PASS{Colors.END}" if result else f"{Colors.RED}FAIL{Colors.END}"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    total = len(results)
    print(f"\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print(f"{Colors.GREEN}All fixes are working correctly!{Colors.END}")
    elif passed >= total * 0.75:
        print(f"{Colors.YELLOW}Most fixes are working - some may need manual attention{Colors.END}")
    else:
        print(f"{Colors.RED}Many fixes are not working - check the masterfix.py script{Colors.END}")

if __name__ == "__main__":
    main()