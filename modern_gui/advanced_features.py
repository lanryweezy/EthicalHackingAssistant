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
    
    def __init__(self, logger: logging.Logger):
        """Initializes the AutomationEngine.

        Args:
            logger: The logger instance for logging messages.
        """
        self.logger = logger
        self.active_workflows = {}
        self.workflow_templates = self._initialize_workflow_templates()
    
    def _initialize_workflow_templates(self) -> Dict[str, Any]:
        """Initializes predefined workflow templates."""
        self.logger.info("Initializing workflow templates.")
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
    
    def create_workflow(self, name: str, description: str, steps: List[Dict], triggers: List[str], created_by: str) -> Union[str, Dict[str, str]]:
        """Creates a custom workflow and stores it in the database.

        Args:
            name: The name of the workflow.
            description: A description of the workflow.
            steps: A list of steps in the workflow.
            triggers: A list of events that can trigger the workflow.
            created_by: The user who created the workflow.

        Returns:
            The ID of the created workflow, or an error dictionary if creation fails.
        """
        self.logger.info(f"Attempting to create new workflow: {name} by {created_by}")
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
        
        try:
            # Save to database
            conn = sqlite3.connect('ethical_hacking.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO workflows (id, name, description, script, triggers, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (workflow_id, name, description, json.dumps(steps), json.dumps(triggers), created_by))
            
            conn.commit()
            conn.close()
            self.logger.info(f"Workflow {name} created successfully with ID: {workflow_id}")
            
            return workflow_id
        except sqlite3.Error as e:
            self.logger.error(f"Database error creating workflow {name}: {e}", exc_info=True)
            return {'error': f'Database error: {str(e)}'}
        except Exception as e:
            self.logger.exception(f"Unexpected error creating workflow {name}:")
            return {'error': f'An unexpected error occurred: {str(e)}'}
    
    def execute_workflow(self, workflow_id: str, target: str, session_id: Optional[str] = None) -> Dict[str, str]:
        """Executes a workflow with given parameters in a background thread.

        Args:
            workflow_id: The ID of the workflow to execute.
            target: The target for the workflow execution.
            session_id: Optional session ID for collaboration.

        Returns:
            A dictionary indicating the execution status.
        """
        self.logger.info(f"Executing workflow {workflow_id} for target {target}.")
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            self.logger.warning(f"Workflow {workflow_id} not found for execution.")
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
        
        self.logger.info(f"Workflow {workflow_id} started with execution ID: {execution_id}")
        return {'execution_id': execution_id, 'status': 'started'}
    
    def _execute_workflow_steps(self, execution_id: str, workflow: Dict, target: str) -> None:
        """Executes workflow steps sequentially in a separate thread.

        Args:
            execution_id: The ID of the workflow execution.
            workflow: The workflow dictionary containing steps.
            target: The target for the workflow execution.
        """
        execution = self.active_workflows[execution_id]
        steps = json.loads(workflow['script'])
        
        for i, step in enumerate(steps):
            execution['current_step'] = i
            
            # Replace target placeholder
            command = step['command'].format(target=target)
            
            try:
                self.logger.info(f"Executing workflow step {i+1}/{len(steps)}: {command}")
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    timeout=step.get('timeout', 300),
                    check=True # Raise CalledProcessError for non-zero exit codes
                )
                
                step_result = {
                    'step': i,
                    'tool': step['tool'],
                    'command': command,
                    'output': result.stdout + result.stderr,
                    'exit_code': result.returncode,
                    'completed_at': datetime.now().isoformat(),
                    'status': 'success'
                }
                self.logger.info(f"Workflow step {i+1} completed successfully. Exit Code: {result.returncode}")
                
            except subprocess.CalledProcessError as e:
                step_result = {
                    'step': i,
                    'tool': step['tool'],
                    'command': command,
                    'error': f'Command failed with exit code {e.returncode}: {e.cmd}. Output: {e.stdout + e.stderr}',
                    'completed_at': datetime.now().isoformat(),
                    'status': 'failed'
                }
                self.logger.error(f"Workflow step {i+1} failed: {step_result['error']}", exc_info=True)
                execution['status'] = 'failed' # Mark workflow as failed
                execution['error_details'] = step_result['error']
                break # Stop further execution on failure
            except subprocess.TimeoutExpired:
                step_result = {
                    'step': i,
                    'tool': step['tool'],
                    'command': command,
                    'error': 'Command timed out',
                    'completed_at': datetime.now().isoformat(),
                    'status': 'failed'
                }
                self.logger.error(f"Workflow step {i+1} timed out.", exc_info=True)
                execution['status'] = 'failed' # Mark workflow as failed
                execution['error_details'] = step_result['error']
                break # Stop further execution on failure
            except FileNotFoundError:
                step_result = {
                    'step': i,
                    'tool': step['tool'],
                    'command': command,
                    'error': f'Command not found: {command.split()[0]}',
                    'completed_at': datetime.now().isoformat(),
                    'status': 'failed'
                }
                self.logger.error(f"Workflow step {i+1} command not found: {command.split()[0]}", exc_info=True)
                execution['status'] = 'failed' # Mark workflow as failed
                execution['error_details'] = step_result['error']
                break # Stop further execution on failure
            except Exception as e:
                step_result = {
                    'step': i,
                    'tool': step['tool'],
                    'command': command,
                    'error': str(e),
                    'completed_at': datetime.now().isoformat(),
                    'status': 'failed'
                }
                self.logger.exception(f"An unexpected error occurred during workflow step {i+1}:")
                execution['status'] = 'failed' # Mark workflow as failed
                execution['error_details'] = step_result['error']
                break # Stop further execution on failure
        
            execution['results'].append(step_result)
            
            # Check for vulnerabilities or triggers
            self._check_triggers(step_result, execution_id)
        
        if execution['status'] != 'failed': # Only set to completed if no step failed
            execution['status'] = 'completed'
        execution['completed_at'] = datetime.now().isoformat()
    
    def _check_triggers(self, step_result: Dict, execution_id: str) -> None:
        """Checks for triggers based on step results and initiates events.

        Args:
            step_result: The result of the executed step.
            execution_id: The ID of the workflow execution.
        """
        self.logger.debug(f"Checking triggers for step result in execution {execution_id}.")
        output = step_result.get('output', '').lower()
        
        # Example trigger detection
        if 'open' in output and 'port' in output:
            self.logger.info(f"Triggering 'port_scan_complete' event for execution {execution_id}.")
            self._trigger_event('port_scan_complete', step_result, execution_id)
        
        if 'vulnerability' in output or 'exploit' in output:
            self.logger.info(f"Triggering 'vulnerability_detected' event for execution {execution_id}.")
            self._trigger_event('vulnerability_detected', step_result, execution_id)
    
    def _trigger_event(self, event_type: str, data: Dict, execution_id: str) -> None:
        """Triggers an event for further processing and stores it in the database.

        Args:
            event_type: The type of event to trigger (e.g., 'port_scan_complete').
            data: The data associated with the event.
            execution_id: The ID of the workflow execution.
        """
        self.logger.info(f"Attempting to trigger event: {event_type} for execution ID: {execution_id}")
        event = {
            'id': str(uuid.uuid4()),
            'type': event_type,
            'data': data,
            'execution_id': execution_id,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
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
            self.logger.info(f"Event triggered and stored: {event_type}")
        except sqlite3.Error as e:
            self.logger.error(f"Database error storing event {event_type}: {e}", exc_info=True)
        except Exception as e:
            self.logger.exception(f"Unexpected error triggering event {event_type}:")
    
    def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a workflow by its ID from the database.

        Args:
            workflow_id: The ID of the workflow to retrieve.

        Returns:
            A dictionary representing the workflow, or None if not found.
        """
        self.logger.info(f"Retrieving workflow with ID: {workflow_id}")
        try:
            conn = sqlite3.connect('ethical_hacking.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM workflows WHERE id = ?', (workflow_id,))
            result = cursor.fetchone()
            
            conn.close()
            
            if result:
                self.logger.info(f"Workflow {workflow_id} retrieved successfully.")
                return {
                    'id': result[0],
                    'name': result[1],
                    'description': result[2],
                    'script': result[3],
                    'triggers': result[4],
                    'created_by': result[5],
                    'created_at': result[6]
                }
            else:
                self.logger.warning(f"Workflow {workflow_id} not found.")
                return None
        except sqlite3.Error as e:
            self.logger.error(f"Database error retrieving workflow {workflow_id}: {e}", exc_info=True)
            return {'error': f'Database error: {str(e)}'}
        except Exception as e:
            self.logger.exception(f"Unexpected error retrieving workflow {workflow_id}:")
            return {'error': f'An unexpected error occurred: {str(e)}'}
    
    def get_execution_status(self, execution_id: str) -> Dict[str, Any]:
        """Gets the current status of a workflow execution.

        Args:
            execution_id: The ID of the workflow execution.

        Returns:
            A dictionary containing the execution status, or an error if not found.
        """
        self.logger.info(f"Retrieving execution status for ID: {execution_id}")
        status = self.active_workflows.get(execution_id, {'error': 'Execution not found'})
        if 'error' in status:
            self.logger.warning(f"Execution status not found for ID: {execution_id}")
        else:
            self.logger.info(f"Execution status for {execution_id}: {status.get('status')}")
        return status

    def get_all_scenarios(self) -> List[Dict[str, Any]]:
        """Retrieves all stored workflows (scenarios) from the database.

        Returns:
            A list of dictionaries, each representing a scenario.
        """
        self.logger.info("Retrieving all scenarios from the database.")
        try:
            conn = sqlite3.connect('ethical_hacking.db')
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, description, created_by, created_at FROM workflows')
            results = cursor.fetchall()
            conn.close()

            scenarios = []
            for row in results:
                scenarios.append({
                    'id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'created_by': row[3],
                    'created_at': row[4]
                })
            self.logger.info(f"Found {len(scenarios)} scenarios.")
            return scenarios
        except sqlite3.Error as e:
            self.logger.error(f"Database error retrieving all scenarios: {e}", exc_info=True)
            return []
        except Exception as e:
            self.logger.exception("Unexpected error retrieving all scenarios:")
            return []


class CollaborationManager:
    """Real-time collaboration features for team assessments"""
    
    def __init__(self, logger: logging.Logger):
        """Initializes the CollaborationManager.

        Args:
            logger: The logger instance for logging messages.
        """
        self.logger = logger
        self.active_sessions = {}
        self.session_participants = {}
    
    def create_session(self, name: str, description: str, created_by: str) -> Union[str, Dict[str, str]]:
        """Creates a new collaboration session and stores it in the database.

        Args:
            name: The name of the session.
            description: A description of the session.
            created_by: The user who created the session.

        Returns:
            The ID of the created session, or an error dictionary if creation fails.
        """
        self.logger.info(f"Attempting to create new session: {name} by {created_by}")
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
        
        try:
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
            self.logger.info(f"Session {name} created successfully with ID: {session_id}")
            
            self.active_sessions[session_id] = session
            self.session_participants[session_id] = [created_by]
            
            return session_id
        except sqlite3.Error as e:
            self.logger.error(f"Database error creating session {name}: {e}", exc_info=True)
            return {'error': f'Database error: {str(e)}'}
        except Exception as e:
            self.logger.exception(f"Unexpected error creating session {name}:")
            return {'error': f'An unexpected error occurred: {str(e)}'}
    
    def join_session(self, session_id: str, user_id: str):
        """Join an existing collaboration session"""
        self.logger.info(f"User {user_id} attempting to join session {session_id}")
        if session_id not in self.active_sessions:
            self.logger.warning(f"Attempted to join non-existent session: {session_id}")
            return {'error': 'Session not found'}
        
        try:
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
                self.logger.info(f"User {user_id} joined session {session_id} successfully.")
            else:
                self.logger.info(f"User {user_id} already in session {session_id}.")
            
            return {'status': 'joined', 'session': self.active_sessions[session_id]}
        except sqlite3.Error as e:
            self.logger.error(f"Database error joining session {session_id}: {e}", exc_info=True)
            return {'error': f'Database error: {str(e)}'}
        except Exception as e:
            self.logger.exception(f"Unexpected error joining session {session_id}:")
            return {'error': f'An unexpected error occurred: {str(e)}'}
    
    def broadcast_to_session(self, session_id: str, message: Dict, sender_id: str):
        """Broadcast message to all session participants"""
        self.logger.info(f"Broadcasting message to session {session_id} from {sender_id}")
        if session_id not in self.active_sessions:
            self.logger.warning(f"Attempted to broadcast to non-existent session: {session_id}")
            return {'error': 'Session not found'}
        
        broadcast_message = {
            'id': str(uuid.uuid4()),
            'session_id': session_id,
            'sender_id': sender_id,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        # In a real implementation, this would use WebSocket broadcasting
        self.logger.info(f"Message broadcasted in session {session_id}.")
        return {'status': 'broadcasted', 'message': broadcast_message}
    
    def get_session_info(self, session_id: str):
        """Get session information"""
        self.logger.info(f"Retrieving session info for session {session_id}")
        session_info = self.active_sessions.get(session_id)
        if not session_info:
            self.logger.warning(f"Session {session_id} not found.")
            return {'error': 'Session not found'}
        self.logger.info(f"Session info retrieved for session {session_id}.")
        return session_info


class EnhancedReportGenerator:
    """Advanced reporting with templates and export options"""
    
    def __init__(self, logger, report_folder):
        self.logger = logger
        self.report_folder = report_folder
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
    
    report_id = str(uuid.uuid4())
        filename = f"report_{report_id}.{format}"
        report_path = os.path.join(self.report_folder, filename)

        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self.logger.info(f"Report {report_id} generated and saved to {report_path}")

            # Save report metadata to database
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
            self.logger.info(f"Report metadata for {report_id} saved to database.")

        except Exception as e:
            self.logger.error(f"Error saving report {report_id}: {e}", exc_info=True)
            return {'error': f'Failed to save report: {str(e)}'}
        
        return {
            'report_id': report_id,
            'content': content,
            'format': format,
            'path': report_path
        }
    
    def export_report(self, report_id: str, export_format: str):
        """Export report in different formats"""
        # In a real implementation, you would fetch the report content from the database
        # For now, we assume the report is already saved to a file by generate_report
        
        report_path = os.path.join(self.report_folder, f"report_{report_id}.html") # Assuming default html
        if not os.path.exists(report_path):
            return {'error': 'Report file not found'}

        if export_format == 'pdf':
            # In a real implementation, convert to PDF using libraries like weasyprint
            filename = f"report_{report_id}.pdf"
            return {'filename': filename, 'path': os.path.join(self.report_folder, filename)}
        
        elif export_format == 'docx':
            # In a real implementation, convert to Word document
            filename = f"report_{report_id}.docx"
            return {'filename': filename, 'path': os.path.join(self.report_folder, filename)}
        
        return {'filename': f"report_{report_id}.html", 'path': report_path}

    def get_report_path(self, report_id: str) -> Optional[str]:
        """Retrieves the file path of a generated report from the database."""
        self.logger.info(f"Attempting to retrieve report path for report ID: {report_id}")
        conn = sqlite3.connect('ethical_hacking.db')
        cursor = conn.cursor()
        cursor.execute('SELECT format, id FROM reports WHERE id = ?', (report_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            report_format = result[0]
            report_filename = f"report_{report_id}.{report_format}"
            report_path = os.path.join(self.report_folder, report_filename)
            self.logger.info(f"Found report path for {report_id}: {report_path}")
            return report_path
        else:
            self.logger.warning(f"Report path not found for report ID: {report_id}")
            return None

    def get_templates(self) -> Dict[str, Any]:
        """Returns a dictionary of available report templates.
        """
        return {
            template_name: {
                "name": self.templates[template_name].get("name", template_name),
                "sections": self.templates[template_name].get("sections", []),
                "format": self.templates[template_name].get("format", [])
            } for template_name in self.templates
        }


class SecurityComplianceChecker:
    """Ensure strict adherence to legal and ethical guidelines"""
    
    def __init__(self, logger):
        self.logger = logger
        self.compliance_rules = self._load_compliance_rules()
        self.restricted_commands = self._load_restricted_commands()
    
    def _load_compliance_rules(self):
        """Load compliance and ethical guidelines"""
        self.logger.info("Loading compliance rules.")
        try:
            # In a real scenario, these might be loaded from a config file or database
            rules = {
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
            self.logger.info("Compliance rules loaded successfully.")
            return rules
        except Exception as e:
            self.logger.error(f"Error loading compliance rules: {e}", exc_info=True)
            return {}
    
    def _load_restricted_commands(self):
        """Load list of potentially dangerous commands"""
        self.logger.info("Loading restricted commands.")
        try:
            commands = [
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
            self.logger.info("Restricted commands loaded successfully.")
            return commands
        except Exception as e:
            self.logger.error(f"Error loading restricted commands: {e}", exc_info=True)
            return []
    
    def check_command_compliance(self, command: str, user_context: Dict):
        """Check if command complies with ethical guidelines"""
        self.logger.info(f"Checking compliance for command: '{command}'")
        command_lower = command.lower()
        
        try:
            # Check for restricted commands
            for restricted in self.restricted_commands:
                if restricted.lower() in command_lower:
                    self.logger.warning(f"Command '{command}' contains restricted pattern: {restricted}")
                    return {
                        'allowed': False,
                        'reason': f'Command contains restricted pattern: {restricted}',
                        'compliance_violation': 'potentially_destructive'
                    }
            
            # Check for authorization requirements
            network_commands = ['nmap', 'masscan', 'nikto', 'sqlmap', 'hydra']
            if any(tool in command_lower for tool in network_commands):
                if not user_context.get('has_authorization', False):
                    self.logger.warning(f"Command '{command}' requires authorization but none provided.")
                    return {
                        'allowed': False,
                        'reason': 'Network scanning requires explicit authorization',
                        'compliance_violation': 'unauthorized_testing',
                        'required_action': 'obtain_authorization'
                    }
            
            # Check target scope
            target = self._extract_target(command)
            if target and not self._is_target_authorized(target, user_context):
                self.logger.warning(f"Command '{command}' targets {target} which is outside authorized scope.")
                return {
                    'allowed': False,
                    'reason': f'Target {target} is not in authorized scope',
                    'compliance_violation': 'scope_violation'
                }
            
            self.logger.info(f"Command '{command}' is compliant.")
            return {
                'allowed': True,
                'compliance_notes': self._get_compliance_reminders(command)
            }
        except Exception as e:
            self.logger.exception(f"Error checking command compliance for '{command}':")
            return {'allowed': False, 'error': f'An unexpected error occurred: {str(e)}'}
    
    def _extract_target(self, command: str):
        """Extract target from command"""
        self.logger.debug(f"Attempting to extract target from command: '{command}'")
        # Simple regex to find IP addresses or domains
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        
        ip_match = re.search(ip_pattern, command)
        domain_match = re.search(domain_pattern, command)
        
        target = ip_match.group() if ip_match else (domain_match.group() if domain_match else None)
        if target:
            self.logger.debug(f"Extracted target: {target}")
        else:
            self.logger.debug("No target extracted.")
        return target
    
    def _is_target_authorized(self, target: str, user_context: Dict):
        """Check if target is in authorized scope"""
        self.logger.debug(f"Checking if target '{target}' is authorized.")
        authorized_targets = user_context.get('authorized_targets', [])
        is_authorized = target in authorized_targets or any(target.endswith(auth_target) for auth_target in authorized_targets)
        if is_authorized:
            self.logger.debug(f"Target '{target}' is authorized.")
        else:
            self.logger.warning(f"Target '{target}' is NOT authorized.")
        return is_authorized
    
    def _get_compliance_reminders(self, command: str):
        """Get relevant compliance reminders for command"""
        self.logger.debug(f"Getting compliance reminders for command: '{command}'")
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
        
        self.logger.debug(f"Generated {len(reminders)} compliance reminders.")
        return reminders
    
    def generate_compliance_report(self, session_id: str):
        """Generate compliance report for a session"""
        self.logger.info(f"Generating compliance report for session: {session_id}")
        # Fetch session data and generate compliance report
        try:
            report = {
                'session_id': session_id,
                'compliance_status': 'compliant',
                'issues_identified': [],
                'recommendations': self.compliance_rules
            }
            self.logger.info(f"Compliance report generated for session: {session_id}")
            return report
        except Exception as e:
            self.logger.error(f"Error generating compliance report for session {session_id}: {e}", exc_info=True)
            return {'error': f'Failed to generate compliance report: {str(e)}'}


# Global instances
automation_engine = AutomationEngine()
collaboration_manager = CollaborationManager()
report_generator = EnhancedReportGenerator()
compliance_checker = SecurityComplianceChecker()
