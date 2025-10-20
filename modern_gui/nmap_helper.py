#!/usr/bin/env python3
"""
Nmap Helper Module - Comprehensive Nmap command generation and assistance
Based on the Cybersources Nmap Cheat Sheet
"""

import re
from typing import List, Dict, Any, Optional
import logging

class NmapHelper:
    """Comprehensive Nmap command helper with cheat sheet integration"""
    
    def __init__(self, logger):
        self.logger = logger
        self.scan_types = {
            'discover_hosts': {
                'name': 'Discover Live Hosts',
                'commands': {
                    'ping_syn': {
                        'cmd': 'nmap -PS22-25,80 {target}',
                        'description': 'Discover hosts by TCP SYN packets to specified ports (22-25 and 80)',
                        'use_case': 'Best for discovering hosts behind firewalls'
                    },
                    'ping_disable': {
                        'cmd': 'nmap -Pn {target}',
                        'description': 'Disable port discovery. Treat all hosts as online',
                        'use_case': 'When ping is blocked but hosts are known to be up'
                    },
                    'icmp_echo': {
                        'cmd': 'nmap -PE {target}',
                        'description': 'Send ICMP Echo packets to discover hosts',
                        'use_case': 'Traditional ping discovery method'
                    },
                    'ping_scan': {
                        'cmd': 'nmap -sn {target}',
                        'description': 'Ping scan - no port scan, just host discovery',
                        'use_case': 'Quick network reconnaissance'
                    }
                }
            },
            
            'scan_targets': {
                'name': 'Scan IP Addresses (Targets)',
                'commands': {
                    'single_host': {
                        'cmd': 'nmap {target}',
                        'description': 'Scan a single host IP',
                        'example': 'nmap 10.0.0.1'
                    },
                    'subnet_range': {
                        'cmd': 'nmap {target}/24',
                        'description': 'Scan a Class C subnet range',
                        'example': 'nmap 192.168.1.0/24'
                    },
                    'ip_range': {
                        'cmd': 'nmap 10.1.1.1-100',
                        'description': 'Scan the range of IPs between 10.1.1.1 up to 10.1.1.100',
                        'example': 'nmap 10.1.1.1-100'
                    },
                    'from_file': {
                        'cmd': 'nmap -iL hosts.txt',
                        'description': 'Scan the IP addresses listed in text file "hosts.txt"',
                        'example': 'nmap -iL targets.txt'
                    },
                    'specific_ips': {
                        'cmd': 'nmap 10.1.1.3 10.1.1.6 10.1.1.8',
                        'description': 'Scan the 3 specified IPs only',
                        'example': 'nmap 192.168.1.1 192.168.1.5 192.168.1.10'
                    },
                    'domain_resolve': {
                        'cmd': 'nmap www.somedomain.com',
                        'description': 'First resolve the IP of the domain and then scan its IP address',
                        'example': 'nmap www.example.com'
                    }
                }
            },
            
            'scan_types': {
                'name': 'Different Scan Types',
                'commands': {
                    'syn_scan': {
                        'cmd': 'nmap -sS {target}',
                        'description': 'TCP SYN Scan (best option)',
                        'use_case': 'Stealthy, fast, doesn\'t complete TCP handshake'
                    },
                    'tcp_connect': {
                        'cmd': 'nmap -sT {target}',
                        'description': 'Full TCP connect scan',
                        'use_case': 'When SYN scan is not available (non-root)'
                    },
                    'udp_scan': {
                        'cmd': 'nmap -sU {target}',
                        'description': 'Scan UDP ports',
                        'use_case': 'Discover UDP services like DNS, DHCP, SNMP'
                    },
                    'ping_only': {
                        'cmd': 'nmap -sP {target}',
                        'description': 'Do a Ping scan only',
                        'use_case': 'Quick host discovery without port scanning'
                    },
                    'no_ping': {
                        'cmd': 'nmap -Pn {target}',
                        'description': 'Don\'t ping the hosts, assume they are up',
                        'use_case': 'When ICMP is blocked but hosts are known to be online'
                    }
                }
            },
            
            'port_scanning': {
                'name': 'Port Related Commands',
                'commands': {
                    'single_port': {
                        'cmd': 'nmap -p80 {target}',
                        'description': 'Scan only port 80 for specified host',
                        'example': 'nmap -p443 192.168.1.1'
                    },
                    'port_range': {
                        'cmd': 'nmap -p20-23 {target}',
                        'description': 'Scan ports 20 up to 23 for specified host',
                        'example': 'nmap -p1-1000 192.168.1.1'
                    },
                    'multiple_ports': {
                        'cmd': 'nmap -p80,88,8000 {target}',
                        'description': 'Scan ports 80, 88, and 8000 only',
                        'example': 'nmap -p22,80,443,8080 192.168.1.1'
                    },
                    'all_ports': {
                        'cmd': 'nmap -p- {target}',
                        'description': 'Scan ALL ports for specified host',
                        'example': 'nmap -p- 192.168.1.1'
                    },
                    'common_ports': {
                        'cmd': 'nmap -sS -sU -p U:53,T:22 {target}',
                        'description': 'Scan ports UDP 53 and TCP 22',
                        'example': 'nmap -sS -sU -p U:161,T:80,T:443 192.168.1.1'
                    },
                    'http_ssh': {
                        'cmd': 'nmap -p http,ssh {target}',
                        'description': 'Scan http and ssh ports for specified host',
                        'example': 'nmap -p ssh,telnet,http,https 192.168.1.1'
                    }
                }
            },
            
            'output_formats': {
                'name': 'Output Types',
                'commands': {
                    'normal': {
                        'cmd': 'nmap -oN [filename] {target}',
                        'description': 'Normal text format',
                        'example': 'nmap -oN scan_results.txt 192.168.1.1'
                    },
                    'grepable': {
                        'cmd': 'nmap -oG [filename] {target}',
                        'description': 'Grepable file (useful to search inside file)',
                        'example': 'nmap -oG scan_results.gnmap 192.168.1.1'
                    },
                    'xml': {
                        'cmd': 'nmap -oX [filename] {target}',
                        'description': 'XML file',
                        'example': 'nmap -oX scan_results.xml 192.168.1.1'
                    },
                    'all_formats': {
                        'cmd': 'nmap -oA [filename] {target}',
                        'description': 'Output in all 3 formats supported',
                        'example': 'nmap -oA complete_scan 192.168.1.1'
                    }
                }
            },
            
            'advanced_scans': {
                'name': 'Advanced Scan Types',
                'commands': {
                    'version_detection': {
                        'cmd': 'nmap -sV {target}',
                        'description': 'Version detection scan of open ports (services)',
                        'use_case': 'Identify service versions for vulnerability assessment'
                    },
                    'os_detection': {
                        'cmd': 'nmap -O {target}',
                        'description': 'Identify Operating System version',
                        'use_case': 'OS fingerprinting for targeted attacks'
                    },
                    'aggressive': {
                        'cmd': 'nmap -A {target}',
                        'description': 'Combines OS detection, service version detection, script scanning, and traceroute',
                        'use_case': 'Comprehensive scan with maximum information gathering'
                    },
                    'script_scan': {
                        'cmd': 'nmap -sC {target}',
                        'description': 'Run default NSE scripts',
                        'use_case': 'Vulnerability detection and service enumeration'
                    },
                    'vuln_scan': {
                        'cmd': 'nmap --script vuln {target}',
                        'description': 'Run vulnerability detection scripts',
                        'use_case': 'Identify known vulnerabilities'
                    },
                    'custom_script': {
                        'cmd': 'nmap --script [script-name] {target}',
                        'description': 'Run specific NSE script',
                        'example': 'nmap --script http-enum 192.168.1.1'
                    }
                }
            }
        }
        
        # Common Nmap NSE scripts
        self.nse_scripts = {
            'web': [
                'http-enum', 'http-headers', 'http-methods', 'http-robots.txt',
                'http-title', 'http-server-header', 'http-backup-finder',
                'http-config-backup', 'http-sql-injection', 'http-csrf'
            ],
            'smb': [
                'smb-enum-shares', 'smb-enum-users', 'smb-os-discovery',
                'smb-security-mode', 'smb-vuln-ms17-010', 'smb-vuln-ms08-067'
            ],
            'ftp': [
                'ftp-anon', 'ftp-bounce', 'ftp-brute', 'ftp-syst', 'ftp-vsftpd-backdoor'
            ],
            'ssh': [
                'ssh-brute', 'ssh-hostkey', 'ssh-auth-methods', 'ssh2-enum-algos'
            ],
            'dns': [
                'dns-brute', 'dns-zone-transfer', 'dns-recursion', 'dns-cache-snoop'
            ],
            'vuln': [
                'vuln', 'vulscan', 'vulners', 'ms-sql-info', 'mysql-info'
            ]
        }
        
        # Timing templates
        self.timing_templates = {
            'T0': 'Paranoid (0) - Very slow scan to avoid IDS detection',
            'T1': 'Sneaky (1) - Slow scan to avoid IDS detection',
            'T2': 'Polite (2) - Slow scan that uses less bandwidth',
            'T3': 'Normal (3) - Default timing template',
            'T4': 'Aggressive (4) - Fast scan for reliable networks',
            'T5': 'Insane (5) - Very fast scan for very reliable networks'
        }
    
    def suggest_scan_command(self, target: str, scan_purpose: str = "general") -> Dict[str, Any]:
        """Suggest appropriate Nmap command based on target and purpose"""
        suggestions = []
        
        # Basic validation
        if not target:
            return {"error": "Target is required"}
        
        # Determine scan type based on purpose
        if scan_purpose.lower() in ["discovery", "recon", "reconnaissance"]:
            suggestions.extend([
                {
                    'command': f'nmap -sn {target}',
                    'description': 'Host discovery scan (ping sweep)',
                    'purpose': 'Quick network reconnaissance'
                },
                {
                    'command': f'nmap -sS -T4 --top-ports 1000 {target}',
                    'description': 'Fast SYN scan of top 1000 ports',
                    'purpose': 'Quick port discovery'
                }
            ])
        
        elif scan_purpose.lower() in ["web", "http", "website"]:
            suggestions.extend([
                {
                    'command': f'nmap -sS -sV -p 80,443,8080,8443 {target}',
                    'description': 'Scan common web ports with version detection',
                    'purpose': 'Web service discovery'
                },
                {
                    'command': f'nmap --script http-enum,http-headers,http-methods -p 80,443 {target}',
                    'description': 'Web enumeration with NSE scripts',
                    'purpose': 'Web application reconnaissance'
                }
            ])
        
        elif scan_purpose.lower() in ["vuln", "vulnerability", "security"]:
            suggestions.extend([
                {
                    'command': f'nmap -sS -sV --script vuln {target}',
                    'description': 'Vulnerability scan with service detection',
                    'purpose': 'Security assessment'
                },
                {
                    'command': f'nmap -A -T4 {target}',
                    'description': 'Aggressive scan with OS detection and scripts',
                    'purpose': 'Comprehensive security scan'
                }
            ])
        
        else:  # General purpose
            suggestions.extend([
                {
                    'command': f'nmap -sS -sV -O {target}',
                    'description': 'SYN scan with version and OS detection',
                    'purpose': 'General reconnaissance'
                },
                {
                    'command': f'nmap -A -T4 {target}',
                    'description': 'Aggressive scan (OS, version, scripts, traceroute)',
                    'purpose': 'Comprehensive information gathering'
                },
                {
                    'command': f'nmap -p- -T4 {target}',
                    'description': 'Scan all 65535 ports',
                    'purpose': 'Complete port discovery'
                }
            ])
        
        return {
            'target': target,
            'purpose': scan_purpose,
            'suggestions': suggestions,
            'timing_info': 'Add timing template (e.g., -T4 for aggressive) for faster scans',
            'output_info': 'Add output options: -oA filename for all formats'
        }
    
    def get_scan_by_category(self, category: str) -> Dict[str, Any]:
        """Get all scan commands for a specific category"""
        if category not in self.scan_types:
            return {"error": f"Category '{category}' not found. Available: {list(self.scan_types.keys())}"}
        
        return self.scan_types[category]
    
    def get_nse_scripts_by_service(self, service: str) -> List[str]:
        """Get NSE scripts relevant to a specific service"""
        service_lower = service.lower()
        if service_lower in self.nse_scripts:
            return self.nse_scripts[service_lower]
        
        # Search for partial matches
        matches = []
        for category, scripts in self.nse_scripts.items():
            if service_lower in category or category in service_lower:
                matches.extend(scripts)
        
        return matches
    
    def build_custom_command(self, target: str, **options) -> str:
        """Build custom Nmap command with specified options"""
        cmd_parts = ['nmap']
        
        # Scan type
        if options.get('syn_scan', True):
            cmd_parts.append('-sS')
        elif options.get('tcp_connect'):
            cmd_parts.append('-sT')
        elif options.get('udp_scan'):
            cmd_parts.append('-sU')
        
        # Discovery options
        if options.get('no_ping'):
            cmd_parts.append('-Pn')
        elif options.get('ping_only'):
            cmd_parts.append('-sn')
        
        # Port options
        if options.get('all_ports'):
            cmd_parts.append('-p-')
        elif options.get('top_ports'):
            cmd_parts.append(f"--top-ports {options['top_ports']}")
        elif options.get('ports'):
            cmd_parts.append(f"-p {options['ports']}")
        
        # Detection options
        if options.get('version_scan'):
            cmd_parts.append('-sV')
        if options.get('os_detection'):
            cmd_parts.append('-O')
        if options.get('aggressive'):
            cmd_parts.append('-A')
        
        # Scripts
        if options.get('default_scripts'):
            cmd_parts.append('-sC')
        elif options.get('script'):
            cmd_parts.append(f"--script {options['script']}")
        
        # Timing
        if options.get('timing'):
            cmd_parts.append(f"-T{options['timing']}")
        
        # Output
        if options.get('output_all'):
            cmd_parts.append(f"-oA {options['output_all']}")
        elif options.get('output_normal'):
            cmd_parts.append(f"-oN {options['output_normal']}")
        
        # Target
        cmd_parts.append(target)
        
        return ' '.join(cmd_parts)
    
    def get_cheat_sheet(self) -> Dict[str, Any]:
        """Get the complete Nmap cheat sheet"""
        return {
            'scan_types': self.scan_types,
            'nse_scripts': self.nse_scripts,
            'timing_templates': self.timing_templates,
            'quick_reference': {
                'basic_scans': [
                    'nmap [target] - Basic scan',
                    'nmap -sS [target] - SYN scan',
                    'nmap -sU [target] - UDP scan',
                    'nmap -A [target] - Aggressive scan'
                ],
                'discovery': [
                    'nmap -sn [target] - Ping scan',
                    'nmap -Pn [target] - No ping',
                    'nmap -PS22-25,80 [target] - TCP SYN ping'
                ],
                'port_scanning': [
                    'nmap -p- [target] - All ports',
                    'nmap -p80,443 [target] - Specific ports',
                    'nmap --top-ports 1000 [target] - Top ports'
                ]
            }
        }
    
    def suggest_scan_command(self, target: str, scan_purpose: str = "general") -> Dict[str, Any]:
        self.logger.info(f"Suggesting Nmap command for target: {target}, purpose: {scan_purpose}")
        suggestions = []
        
        # Basic validation
        if not target:
            self.logger.warning("Target is required for Nmap command suggestion.")
            return {"error": "Target is required"}
        
        # Determine scan type based on purpose
        if scan_purpose.lower() in ["discovery", "recon", "reconnaissance"]:
            suggestions.extend([
                {
                    'command': f'nmap -sn {target}',
                    'description': 'Host discovery scan (ping sweep)',
                    'purpose': 'Quick network reconnaissance'
                },
                {
                    'command': f'nmap -sS -T4 --top-ports 1000 {target}',
                    'description': 'Fast SYN scan of top 1000 ports',
                    'purpose': 'Quick port discovery'
                }
            ])
        
        elif scan_purpose.lower() in ["web", "http", "website"]:
            suggestions.extend([
                {
                    'command': f'nmap -sS -sV -p 80,443,8080,8443 {target}',
                    'description': 'Scan common web ports with version detection',
                    'purpose': 'Web service discovery'
                },
                {
                    'command': f'nmap --script http-enum,http-headers,http-methods -p 80,443 {target}',
                    'description': 'Web enumeration with NSE scripts',
                    'purpose': 'Web application reconnaissance'
                }
            ])
        
        elif scan_purpose.lower() in ["vuln", "vulnerability", "security"]:
            suggestions.extend([
                {
                    'command': f'nmap -sS -sV --script vuln {target}',
                    'description': 'Vulnerability scan with service detection',
                    'purpose': 'Security assessment'
                },
                {
                    'command': f'nmap -A -T4 {target}',
                    'description': 'Aggressive scan with OS detection and scripts',
                    'purpose': 'Comprehensive security scan'
                }
            ])
        
        else:  # General purpose
            suggestions.extend([
                {
                    'command': f'nmap -sS -sV -O {target}',
                    'description': 'SYN scan with version and OS detection',
                    'purpose': 'General reconnaissance'
                },
                {
                    'command': f'nmap -A -T4 {target}',
                    'description': 'Aggressive scan (OS, version, scripts, traceroute)',
                    'purpose': 'Comprehensive information gathering'
                },
                {
                    'command': f'nmap -p- -T4 {target}',
                    'description': 'Scan all 65535 ports',
                    'purpose': 'Complete port discovery'
                }
            ])
        
        self.logger.info(f"Generated {len(suggestions)} Nmap suggestions.")
        return {
            'target': target,
            'purpose': scan_purpose,
            'suggestions': suggestions,
            'timing_info': 'Add timing template (e.g., -T4 for aggressive) for faster scans',
            'output_info': 'Add output options: -oA filename for all formats'
        }
    
    def get_scan_by_category(self, category: str) -> Dict[str, Any]:
        self.logger.info(f"Getting Nmap scans by category: {category}")
        if category not in self.scan_types:
            self.logger.warning(f"Category '{category}' not found in Nmap scan types.")
            return {"error": f"Category '{category}' not found. Available: {list(self.scan_types.keys())}"}
        
        return self.scan_types[category]
    
    def get_nse_scripts_by_service(self, service: str) -> List[str]:
        self.logger.info(f"Getting NSE scripts for service: {service}")
        service_lower = service.lower()
        if service_lower in self.nse_scripts:
            return self.nse_scripts[service_lower]
        
        # Search for partial matches
        matches = []
        for category, scripts in self.nse_scripts.items():
            if service_lower in category or category in service_lower:
                matches.extend(scripts)
        
        self.logger.info(f"Found {len(matches)} NSE scripts for service: {service}")
        return matches
    
    def build_custom_command(self, target: str, **options) -> str:
        self.logger.info(f"Building custom Nmap command for target: {target}, options: {options}")
        cmd_parts = ['nmap']
        
        # Scan type
        if options.get('syn_scan', True):
            cmd_parts.append('-sS')
        elif options.get('tcp_connect'):
            cmd_parts.append('-sT')
        elif options.get('udp_scan'):
            cmd_parts.append('-sU')
        
        # Discovery options
        if options.get('no_ping'):
            cmd_parts.append('-Pn')
        elif options.get('ping_only'):
            cmd_parts.append('-sn')
        
        # Port options
        if options.get('all_ports'):
            cmd_parts.append('-p-')
        elif options.get('top_ports'):
            cmd_parts.append(f"--top-ports {options['top_ports']}")
        elif options.get('ports'):
            cmd_parts.append(f"-p {options['ports']}")
        
        # Detection options
        if options.get('version_scan'):
            cmd_parts.append('-sV')
        if options.get('os_detection'):
            cmd_parts.append('-O')
        if options.get('aggressive'):
            cmd_parts.append('-A')
        
        # Scripts
        if options.get('default_scripts'):
            cmd_parts.append('-sC')
        elif options.get('script'):
            cmd_parts.append(f"--script {options['script']}")
        
        # Timing
        if options.get('timing'):
            cmd_parts.append(f"-T{options['timing']}")
        
        # Output
        if options.get('output_all'):
            cmd_parts.append(f"-oA {options['output_all']}")
        elif options.get('output_normal'):
            cmd_parts.append(f"-oN {options['output_normal']}")
        
        # Target
        cmd_parts.append(target)
        
        self.logger.info(f"Built custom Nmap command: {' '.join(cmd_parts)}")
        return ' '.join(cmd_parts)
    
    def get_cheat_sheet(self) -> Dict[str, Any]:
        self.logger.info("Getting Nmap cheat sheet.")
        return {
            'scan_types': self.scan_types,
            'nse_scripts': self.nse_scripts,
            'timing_templates': self.timing_templates,
            'quick_reference': {
                'basic_scans': [
                    'nmap [target] - Basic scan',
                    'nmap -sS [target] - SYN scan',
                    'nmap -sU [target] - UDP scan',
                    'nmap -A [target] - Aggressive scan'
                ],
                'discovery': [
                    'nmap -sn [target] - Ping scan',
                    'nmap -Pn [target] - No ping',
                    'nmap -PS22-25,80 [target] - TCP SYN ping'
                ],
                'port_scanning': [
                    'nmap -p- [target] - All ports',
                    'nmap -p80,443 [target] - Specific ports',
                    'nmap --top-ports 1000 [target] - Top ports'
                ]
            }
        }
    
    def validate_target(self, target: str) -> Dict[str, Any]:
        self.logger.info(f"Validating Nmap target: {target}")
        valid_patterns = [
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
,  # Single IP
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}
,  # CIDR
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}
,  # IP range
            r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}
  # Domain name
        ]
        
        for pattern in valid_patterns:
            if re.match(pattern, target):
                self.logger.info(f"Target '{target}' is valid.")
                return {
                    'valid': True,
                    'format': pattern,
                    'target': target
                }
        
        self.logger.warning(f"Target '{target}' is invalid.")
        return {
            'valid': False,
            'error': 'Invalid target format. Use IP, CIDR, IP range, or domain name.',
            'examples': [
                '192.168.1.1',
                '192.168.1.0/24',
                '192.168.1.1-100',
                'example.com'
            ]
        }
