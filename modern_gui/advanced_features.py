#!/usr/bin/env python3
"""
Advanced Features for Ethical Hacking Assistant
- Automation Engine
- Collaboration Features
- Event Triggers
- Enhanced Reporting
- Security Compliance
"""

import sqlite3
import json
import yaml
import uuid
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from jinja2 import Template
import subprocess
import os
import logging

logger = logging.getLogger(__name__)

class AutomationEngine:
    """Scripting and automation engine for ethical hacking workflows"""
    
    def __init__(self):
        self.active_workflows = {}
        self.workflow_templates = self._initialize_workflow_templates()
    
    def _initialize_workflow_templates(self):
        """Initialize predefined workflow templates"""
        return {
            'basic_recon': {
                'name': 'Basic Reconnaissance Workflow',
                'description': 'Automated reconnaissance workflow for target assessment',
                'steps': [
                    {'tool': 'nmap', 'command': 'nmap -sS -sV {target}', 'timeout': 300},
                    {'tool': 'nikto', 'command': 'nikto -h {target}', 'timeout': 600},
                    {'tool': 'subfinder', 'command': 'subfinder -d {target}', 'timeout': 180}
                ],
                'triggers': ['port_scan_complete', 'vulnerability_detected']
            },
            'web_app_scan': {
                'name': 'Web Application Security Assessment',
                'description': 'Comprehensive web application security testing',
                'steps': [
                    {'tool': 'dirb', 'command': 'dirb http://{target}/', 'timeout': 300},
                    {'tool': 'sqlmap', 'command': 'sqlmap -u "http://{target}" --batch', 'timeout': 900},
                    {'tool': 'wpscan', 'command': 'wpscan --url http://{target}/', 'timeout': 450}
                ],
                'triggers': ['web_service_detected']
            },
            'network_pentest': {
                'name': 'Network Penetration Test',
                'description': 'Complete network penetration testing workflow',
                'steps': [
                    {'tool': 'masscan', 'command': 'masscan -p1-65535 {target} --rate=1000', 'timeout': 180},
                    {'tool': 'nmap', 'command': 'nmap -A -sV {target}', 'timeout': 600},
                    {'tool': 'enum4linux', 'command': 'enum4linux {target}', 'timeout': 300}
                ],
                'triggers': ['network_scan_complete']
            }
        }
    
    def create_workflow(self, name: str, description: str, steps: List[Dict], triggers: List[str], created_by: str):
        """Create a custom workflow"""
        workflow_id = str(uuid.uuid4())
        
        workflow = {
            'id': workflow_id,
            'name': name,
            'description': description,
            'steps': steps,
            'triggers': triggers,
            'created_by': created_by,
            'created_at': datetime.now().isoformat()
        }
        
        # Save to database
        conn = sqlite3.connect('ethical_hacking.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO workflows (id, name, description, script, triggers, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (workflow_id, name, description, json.dumps(steps), json.dumps(triggers), created_by))
        
        conn.commit()
        conn.close()
        
        return workflow_id
    
    def execute_workflow(self, workflow_id: str, target: str, session_id: str = None):
        """Execute a workflow with given parameters"""
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            return {'error': 'Workflow not found'}
        
        execution_id = str(uuid.uuid4())
        self.active_workflows[execution_id] = {
            'workflow_id': workflow_id,
            'target': target,
            'session_id': session_id,
            'status': 'running',
            'current_step': 0,
            'results': [],
            'started_at': datetime.now().isoformat()
        }
        
        # Start execution in background thread
        thread = threading.Thread(target=self._execute_workflow_steps, 
                                 args=(execution_id, workflow, target))
        thread.start()
        
        return {'execution_id': execution_id, 'status': 'started'}
    
    def _execute_workflow_steps(self, execution_id: str, workflow: Dict, target: str):
        """Execute workflow steps sequentially"""
        execution = self.active_workflows[execution_id]
        steps = json.loads(workflow['script'])
        
        for i, step in enumerate(steps):
            execution['current_step'] = i
            
            # Replace target placeholder
            command = step['command'].format(target=target)
            
            try:
                # Execute command with timeout
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    timeout=step.get('timeout', 300)
                )
                
                step_result = {
                    'step': i,
                    'tool': step['tool'],
                    'command': command,
                    'output': result.stdout + result.stderr,
                    'exit_code': result.returncode,
                    'completed_at': datetime.now().isoformat()
                }
                
                execution['results'].append(step_result)
                
                # Check for vulnerabilities or triggers
                self._check_triggers(step_result, execution_id)
                
            except subprocess.TimeoutExpired:
                step_result = {
                    'step': i,
                    'tool': step['tool'],
                    'command': command,
                    'error': 'Command timed out',
                    'completed_at': datetime.now().isoformat()
                }
                execution['results'].append(step_result)
            
            except Exception as e:
                step_result = {
                    'step': i,
                    'tool': step['tool'],
                    'command': command,
                    'error': str(e),
                    'completed_at': datetime.now().isoformat()
                }
                execution['results'].append(step_result)
        
        execution['status'] = 'completed'
        execution['completed_at'] = datetime.now().isoformat()
    
    def _check_triggers(self, step_result: Dict, execution_id: str):
        """Check for triggers based on step results"""
        output = step_result.get('output', '').lower()
        
        # Example trigger detection
        if 'open' in output and 'port' in output:
            self._trigger_event('port_scan_complete', step_result, execution_id)
        
        if 'vulnerability' in output or 'exploit' in output:
            self._trigger_event('vulnerability_detected', step_result, execution_id)
    
    def _trigger_event(self, event_type: str, data: Dict, execution_id: str):
        """Trigger an event for further processing"""
        event = {
            'id': str(uuid.uuid4()),
            'type': event_type,
            'data': data,
            'execution_id': execution_id,
            'timestamp': datetime.now().isoformat()
        }
        
        # Store in database for event-driven processing
        conn = sqlite3.connect('ethical_hacking.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerabilities (id, target, vulnerability_type, severity, description, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (event['id'], data.get('command', ''), event_type, 'medium', 
              json.dumps(data), 'detected'))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Event triggered: {event_type}")
    
    def get_workflow(self, workflow_id: str):
        """Retrieve workflow by ID"""
        conn = sqlite3.connect('ethical_hacking.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM workflows WHERE id = ?', (workflow_id,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            return {
                'id': result[0],
                'name': result[1],
                'description': result[2],
                'script': result[3],
                'triggers': result[4],
                'created_by': result[5],
                'created_at': result[6]
            }
        return None
    
    def get_execution_status(self, execution_id: str):
        """Get status of workflow execution"""
        return self.active_workflows.get(execution_id, {'error': 'Execution not found'})


class CollaborationManager:
    """Real-time collaboration features for team assessments"""
    
    def __init__(self):
        self.active_sessions = {}
        self.session_participants = {}
    
    def create_session(self, name: str, description: str, created_by: str):
        """Create a new collaboration session"""
        session_id = str(uuid.uuid4())
        
        session = {
            'id': session_id,
            'name': name,
            'description': description,
            'created_by': created_by,
            'participants': [created_by],
            'status': 'active',
            'created_at': datetime.now().isoformat()
        }
        
        # Save to database
        conn = sqlite3.connect('ethical_hacking.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (id, name, description, created_by, participants, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session_id, name, description, created_by, 
              json.dumps(session['participants']), 'active'))
        
        conn.commit()
        conn.close()
        
        self.active_sessions[session_id] = session
        self.session_participants[session_id] = [created_by]
        
        return session_id
    
    def join_session(self, session_id: str, user_id: str):
        """Join an existing collaboration session"""
        if session_id not in self.active_sessions:
            return {'error': 'Session not found'}
        
        if user_id not in self.session_participants[session_id]:
            self.session_participants[session_id].append(user_id)
            self.active_sessions[session_id]['participants'].append(user_id)
            
            # Update database
            conn = sqlite3.connect('ethical_hacking.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE sessions SET participants = ? WHERE id = ?
            ''', (json.dumps(self.session_participants[session_id]), session_id))
            
            conn.commit()
            conn.close()
        
        return {'status': 'joined', 'session': self.active_sessions[session_id]}
    
    def broadcast_to_session(self, session_id: str, message: Dict, sender_id: str):
        """Broadcast message to all session participants"""
        if session_id not in self.active_sessions:
            return {'error': 'Session not found'}
        
        broadcast_message = {
            'id': str(uuid.uuid4()),
            'session_id': session_id,
            'sender_id': sender_id,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        # In a real implementation, this would use WebSocket broadcasting
        return {'status': 'broadcasted', 'message': broadcast_message}
    
    def get_session_info(self, session_id: str):
        """Get session information"""
        return self.active_sessions.get(session_id, {'error': 'Session not found'})


class EnhancedReportGenerator:
    """Advanced reporting with templates and export options"""
    
    def __init__(self):
        self.templates = self._load_report_templates()
    
    def _load_report_templates(self):
        """Load Jinja2 templates for different report formats"""
        return {
            'executive_summary': """
# Executive Summary Report
**Assessment Date:** {{ assessment_date }}
**Target:** {{ target }}
**Assessor:** {{ assessor }}

## Key Findings
{% for finding in findings %}
- **{{ finding.title }}** ({{ finding.severity }})
  - {{ finding.description }}
{% endfor %}

## Risk Assessment
- **High Risk Issues:** {{ risk_counts.high }}
- **Medium Risk Issues:** {{ risk_counts.medium }}
- **Low Risk Issues:** {{ risk_counts.low }}

## Recommendations
{% for recommendation in recommendations %}
1. {{ recommendation }}
{% endfor %}
            """,
            'technical_report': """
# Technical Assessment Report
**Target:** {{ target }}
**Assessment Period:** {{ start_date }} - {{ end_date }}
**Methodology:** {{ methodology }}

## Scope and Limitations
{{ scope }}

## Technical Findings
{% for finding in technical_findings %}
### {{ finding.title }}
**Severity:** {{ finding.severity }}
**CVSS Score:** {{ finding.cvss_score }}

**Description:**
{{ finding.description }}

**Proof of Concept:**
```
{{ finding.poc }}
```

**Remediation:**
{{ finding.remediation }}

---
{% endfor %}

## Tools Used
{% for tool in tools_used %}
- {{ tool.name }}: {{ tool.version }}
{% endfor %}
            """,
            'compliance_report': """
# Compliance Assessment Report
**Framework:** {{ framework }}
**Organization:** {{ organization }}
**Assessment Date:** {{ assessment_date }}

## Compliance Status
{% for control in controls %}
### {{ control.id }}: {{ control.title }}
**Status:** {{ control.status }}
**Implementation Level:** {{ control.implementation_level }}
**Findings:** {{ control.findings }}
**Recommendations:** {{ control.recommendations }}
{% endfor %}

## Overall Compliance Score
**Score:** {{ compliance_score }}%
**Grade:** {{ compliance_grade }}

## Gap Analysis
{% for gap in gaps %}
- **Control {{ gap.control_id }}:** {{ gap.description }}
  - **Impact:** {{ gap.impact }}
  - **Priority:** {{ gap.priority }}
{% endfor %}
            """
        }
    
    def generate_report(self, template_name: str, data: Dict, format: str = 'html'):
        """Generate report from template and data"""
        if template_name not in self.templates:
            return {'error': 'Template not found'}
        
        template = Template(self.templates[template_name])
        content = template.render(**data)
        
        report_id = str(uuid.uuid4())
        
        # Save report to database
        conn = sqlite3.connect('ethical_hacking.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO reports (id, title, content, template, format, created_by, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (report_id, data.get('title', 'Assessment Report'), 
              content, template_name, format, 
              data.get('created_by', 'system'), data.get('session_id', None)))
        
        conn.commit()
        conn.close()
        
        if format == 'pdf':
            # In a real implementation, convert to PDF using libraries like weasyprint
            pass
        
        return {
            'report_id': report_id,
            'content': content,
            'format': format
        }
    
    def export_report(self, report_id: str, export_format: str):
        """Export report in different formats"""
        conn = sqlite3.connect('ethical_hacking.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
        result = cursor.fetchone()
        
        conn.close()
        
        if not result:
            return {'error': 'Report not found'}
        
        content = result[2]  # content column
        
        if export_format == 'pdf':
            # Convert to PDF
            filename = f"report_{report_id}.pdf"
            # In real implementation, use PDF generation library
            return {'filename': filename, 'path': f'/tmp/{filename}'}
        
        elif export_format == 'docx':
            # Convert to Word document
            filename = f"report_{report_id}.docx"
            # In real implementation, use python-docx
            return {'filename': filename, 'path': f'/tmp/{filename}'}
        
        return {'content': content, 'format': export_format}


class SecurityComplianceChecker:
    """Ensure strict adherence to legal and ethical guidelines"""
    
    def __init__(self):
        self.compliance_rules = self._load_compliance_rules()
        self.restricted_commands = self._load_restricted_commands()
    
    def _load_compliance_rules(self):
        """Load compliance and ethical guidelines"""
        return {
            'authorization_required': [
                'Before conducting any security assessment, explicit written authorization must be obtained',
                'Only test systems that you own or have explicit permission to test',
                'Respect scope limitations and do not exceed authorized boundaries'
            ],
            'data_protection': [
                'Do not access, modify, or delete sensitive data during testing',
                'Handle any discovered information with strict confidentiality',
                'Follow data protection regulations (GDPR, CCPA, etc.)'
            ],
            'responsible_disclosure': [
                'Report vulnerabilities responsibly to system owners',
                'Provide reasonable time for remediation before public disclosure',
                'Follow coordinated vulnerability disclosure practices'
            ],
            'legal_compliance': [
                'Comply with all applicable local, state, and federal laws',
                'Understand and follow computer crime laws in your jurisdiction',
                'Maintain proper documentation for legal compliance'
            ]
        }
    
    def _load_restricted_commands(self):
        """Load list of potentially dangerous commands"""
        return [
            'rm -rf /',
            'format c:',
            'dd if=/dev/zero',
            'chmod 777 /',
            'wget * | sh',
            'curl * | bash',
            ':(){ :|:& };:',  # Fork bomb
            'shutdown',
            'reboot',
            'halt'
        ]
    
    def check_command_compliance(self, command: str, user_context: Dict):
        """Check if command complies with ethical guidelines"""
        command_lower = command.lower()
        
        # Check for restricted commands
        for restricted in self.restricted_commands:
            if restricted.lower() in command_lower:
                return {
                    'allowed': False,
                    'reason': f'Command contains restricted pattern: {restricted}',
                    'compliance_violation': 'potentially_destructive'
                }
        
        # Check for authorization requirements
        network_commands = ['nmap', 'masscan', 'nikto', 'sqlmap', 'hydra']
        if any(tool in command_lower for tool in network_commands):
            if not user_context.get('has_authorization', False):
                return {
                    'allowed': False,
                    'reason': 'Network scanning requires explicit authorization',
                    'compliance_violation': 'unauthorized_testing',
                    'required_action': 'obtain_authorization'
                }
        
        # Check target scope
        target = self._extract_target(command)
        if target and not self._is_target_authorized(target, user_context):
            return {
                'allowed': False,
                'reason': f'Target {target} is not in authorized scope',
                'compliance_violation': 'scope_violation'
            }
        
        return {
            'allowed': True,
            'compliance_notes': self._get_compliance_reminders(command)
        }
    
    def _extract_target(self, command: str):
        """Extract target from command"""
        # Simple regex to find IP addresses or domains
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        ip_match = re.search(ip_pattern, command)
        domain_match = re.search(domain_pattern, command)
        
        return ip_match.group() if ip_match else (domain_match.group() if domain_match else None)
    
    def _is_target_authorized(self, target: str, user_context: Dict):
        """Check if target is in authorized scope"""
        authorized_targets = user_context.get('authorized_targets', [])
        return target in authorized_targets or any(target.endswith(auth_target) for auth_target in authorized_targets)
    
    def _get_compliance_reminders(self, command: str):
        """Get relevant compliance reminders for command"""
        reminders = []
        
        if any(tool in command.lower() for tool in ['nmap', 'scan', 'enum']):
            reminders.extend([
                'Ensure you have written authorization to scan this target',
                'Document your testing activities for compliance',
                'Respect rate limits and avoid disrupting services'
            ])
        
        if any(tool in command.lower() for tool in ['exploit', 'attack', 'crack']):
            reminders.extend([
                'Only use exploits against authorized targets',
                'Be prepared to document any successful exploits',
                'Have a remediation plan ready for any vulnerabilities found'
            ])
        
        return reminders
    
    def generate_compliance_report(self, session_id: str):
        """Generate compliance report for a session"""
        # Fetch session data and generate compliance report
        return {
            'session_id': session_id,
            'compliance_status': 'compliant',
            'issues_identified': [],
            'recommendations': self.compliance_rules
        }


# Global instances
automation_engine = AutomationEngine()
collaboration_manager = CollaborationManager()
report_generator = EnhancedReportGenerator()
compliance_checker = SecurityComplianceChecker()
