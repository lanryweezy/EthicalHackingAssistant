#!/usr/bin/env python3
"""
Modern Ethical Hacking Terminal - Flask backend
A futuristic terminal application for pentesters with OpenRouter AI integration
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import os
import sys
import json
import subprocess
import platform
import psutil
import time
from datetime import datetime
import threading
import queue
import requests
import shutil
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import uuid
import sqlite3
import logging
import yaml
from jinja2 import Template
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import secrets
from src.utils.file_utils import allowed_file, secure_filename
from advanced_features.stream_manager import StreamManager
from advanced_features.EnhancedReportGenerator import EnhancedReportGenerator
from advanced_features.AutomationEngine import AutomationEngine
import logging
from src.core.ai_parser import AIParser

from src.core.agent_registry import AgentRegistry
from src.workflows.recon_workflow import ReconWorkflow
from src.agents.recon_agent import ReconAgent
from src.agents.exploit_agent import ExploitAgent
from src.agents.cleanup_agent import CleanupAgent
from src.agents.context_aware_agent import ContextAwareAgent
from src.core.vulnerability_enrichment import VulnerabilityEnrichment


class EthicalHackingAssistant:
    """Main application class for the Ethical Hacking Assistant"""
    
    def __init__(self, platform_tools, logger):
        """Initialize the main application components"""
        # Initialize core components
        self.ai_parser = AIParser(self.logger)
        self.agent_registry = AgentRegistry(self.logger)
        self.platform_tools = platform_tools
        self.logger = logger

        self.nmap_helper = NmapHelper(self.logger)
        self.oscp_resources = OSCPResources(self.logger)
        
        # Set up logging (using app.py's logger)
        
        # Register agents
        self.register_agents()
        
        # CLI-specific initialization removed for Flask backend
        # Register command handlers (if needed for internal logic, otherwise remove)
        # self.register_command_handlers()
    
    
    
    def register_agents(self):
        """Register all available agents"""
        self.agent_registry.register('recon', ReconAgent(self.platform_tools, self.logger))
        self.agent_registry.register('exploit', ExploitAgent(self.platform_tools, self.logger))
        self.agent_registry.register('cleanup', CleanupAgent(self.platform_tools, self.logger))
        
        # Initialize and register the context-aware agent
        self.context_agent = ContextAwareAgent(self.logger)
        self.agent_registry.register('context_aware', self.context_agent)
        
        # Log available agents
        self.logger.info(f"Registered agents: {list(self.agent_registry.agents.keys())}")
    
    def register_command_handlers(self):
        """Register handlers for CLI commands (not directly used in Flask backend)"""
        pass

    # CLI command handlers (removed as not directly used in Flask backend)
    # def handle_agent_command(self, args):
    #     return True
    # def handle_workflow_command(self, args):
    #     return True
    # def handle_target_command(self, args):
    #     return True
    
    def process_command(self, mode, command):
        """Process a user command and update context-aware agent accordingly
        
        Args:
            mode: The current CLI mode
            command: The command text
        Returns:
            Result of command execution (plus learning and suggested next steps)
        """
        try:
            if mode == 'agent':
                # AI interprets and runs
                task = self.ai_parser.parse(command)
                agent = self.agent_registry.get(task['agent'])
                if agent:
                    if agent_name == "nmap_helper": # Handle nmap_helper commands
                        # Example: nmap suggest <target> <purpose>
                        parts = task['command'].split(maxsplit=1)
                        if len(parts) > 1 and parts[0].lower() == "suggest":
                            sub_command = parts[1].strip()
                            sub_parts = sub_command.split(maxsplit=1)
                            target = sub_parts[0] if sub_parts else ""
                            purpose = sub_parts[1] if len(sub_parts) > 1 else "general"
                            result = self.nmap_helper.suggest_scan_command(target, purpose)
                        else:
                            result = "Nmap Helper: Unknown command. Try 'nmap suggest <target> [purpose]'."
                    elif agent_name == "oscp_resources": # Handle oscp_resources commands
                        # Example: oscp methodology
                        if task['command'].lower() == "methodology":
                            result = self.oscp_resources.get_oscp_methodology()
                        else:
                            result = "OSCP Resources: Unknown command. Try 'oscp methodology'."
                    else: # Existing agents
                        result = agent.run(task)
                    # Feed the input/output into context-aware agent for persistent learning
                    if agent == self.context_agent and isinstance(result, dict) and 'data' in result:
                        # Results are already context-updating
                        pass
                    elif agent != self.context_agent:
                        # If another agent, try to pass output to context-agent if possible
                        self.context_agent.update_context(command, str(result))
                    # After every agent run, suggest next actions based on new context
                    next_suggestions = self.context_agent.suggest_next_actions()
                    if next_suggestions:
                        result_str = result if isinstance(result, str) else ''
                        result_str += "\n\n\033[92mAI Suggestions (Next Steps):\033[0m\n"
                        for s in next_suggestions:
                            result_str += f"- {s['action']}: {s['command']}\n  Reason: {s.get('description','')}\n"
                        return result_str
                    return result
                else:
                    return "Could not determine the appropriate agent."

            elif mode == 'terminal':
                # Raw shell command with safety checks
                if self.is_safe_command(command):
                    output, exit_code = self.platform_tools.execute_command(command)
                    # Always push output to the context-aware agent
                    self.context_agent.update_context(command, str(output))
                    # Suggest next steps
                    next_suggestions = self.context_agent.suggest_next_actions()
                    output_str = str(output)
                    if next_suggestions:
                        output_str += "\n\n\033[92mAI Suggestions (Next Steps):\033[0m\n"
                        for s in next_suggestions:
                            output_str += f"- {s['action']}: {s['command']}\n  Reason: {s.get('description','')}\n"
                    return output_str
                else:
                    return "Command rejected for security reasons. Use with caution."

            elif mode == 'more':
                # AI suggests, frontend confirms
                task = self.ai_parser.parse(command)
                self.cli.terminal.print_message(f"AI Suggestion: {task['command']}", "info")
                confirm = self.cli.input_prompt("Run this command? (y/n): ", "warning")
                if confirm.lower() == 'y':
                    output = self.executor.run(task['command'])
                    self.context_agent.update_context(command, str(output))
                    next_suggestions = self.context_agent.suggest_next_actions()
                    output_str = str(output)
                    if next_suggestions:
                        output_str += "\n\n\033[92mAI Suggestions (Next Steps):\033[0m\n"
                        for s in next_suggestions:
                            output_str += f"- {s['action']}: {s['command']}\n  Reason: {s.get('description','')}\n"
                    return output_str
                return "Command cancelled by user."

            elif mode == 'auto':
                # Fully autonomous workflow
                if 'recon' in command.lower():
                    workflow = ReconWorkflow(command, self.platform_tools, self.logger)
                    result = workflow.run()
                    self.context_agent.update_context(command, str(result))
                    next_suggestions = self.context_agent.suggest_next_actions()
                    result_str = str(result)
                    if next_suggestions:
                        result_str += "\n\n\033[92mAI Suggestions (Next Steps):\033[0m\n"
                        for s in next_suggestions:
                            result_str += f"- {s['action']}: {s['command']}\n  Reason: {s.get('description','')}\n"
                    return result_str
                else:
                    return "Auto mode only supports recon workflow for now."
            
            return "Unknown mode. This should not happen."
            
        except Exception as e:
            self.logger.error(f"Error processing command: {e}", exc_info=True)
            return f"An error occurred: {e}"
    
    def is_safe_command(self, command):
        """Check if a command is safe to execute
        
        Args:
            command: The command string
            
        Returns:
            True if the command is considered safe, False otherwise
        """
        # List of potentially dangerous commands/patterns
        dangerous_patterns = [
            "rm -rf", "format", "mkfs", "dd if=", "fdisk", 
            ":(){ :|:& };:", # Fork bomb
            "chmod -R 777 /", "chmod -R 000 /",
            "wget .* | bash", "curl .* | bash",
            "> /dev/sda", "> /dev/hda"
        ]
        
        # Check for dangerous patterns
        for pattern in dangerous_patterns:
            if pattern in command.lower():
                self.logger.warning(f"Potentially dangerous command detected: {command}")
                return False
        
        return True
    
    def run(self):
        """Run the main application"""
        # Start the CLI interface with our command processor
        self.cli.run(command_processor=self.process_command)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our custom modules
try:
    from nmap_helper import NmapHelper
    nmap_helper = NmapHelper()
except ImportError:
    nmap_helper = None
    logger.warning("Nmap helper module not available")

try:
    from oscp_resources import OSCPResources
    oscp_resources = OSCPResources()
except ImportError:
    oscp_resources = None
    logger.warning("OSCP resources module not available")

# New imports for NmapHelper and OSCPResources
from nmap_helper import NmapHelper
from oscp_resources import OSCPResources

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ethical-hacking-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

platform_tools: PlatformTools = PlatformTools(logger)
ethical_hacking_assistant: EthicalHackingAssistant = EthicalHackingAssistant(platform_tools, logger)

# Initialize managers for API routes
scenario_manager: AutomationEngine = AutomationEngine(logger)
tool_manager: EthicalHackingTools = EthicalHackingTools(platform_tools)
report_generator: EnhancedReportGenerator = EnhancedReportGenerator(logger, REPORT_FOLDER)
vulnerability_enrichment: VulnerabilityEnrichment = VulnerabilityEnrichment(logger)
collaboration_manager: CollaborationManager = CollaborationManager(logger)
compliance_checker: SecurityComplianceChecker = SecurityComplianceChecker(logger)

# Command processor queue
command_queue: queue.Queue = queue.Queue()
output_queue: queue.Queue = queue.Queue()

# OpenRouter API configuration
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY', 'YOUR_OPENROUTER_API_KEY')  # Set this via environment variable
OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize database for collaboration and workflows
def init_database() -> None:
    """Initializes the SQLite database for ethical hacking assistant data."""
    conn = None
    try:
        conn = sqlite3.connect('ethical_hacking.db')
        cursor = conn.cursor()
        
        # Users table for collaboration
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                email TEXT,
                role TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Sessions table for collaboration
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                created_by TEXT,
                participants TEXT,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Workflows table for automation
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS workflows (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                script TEXT,
                triggers TEXT,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Reports table for detailed reporting
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                title TEXT,
                content TEXT,
                template TEXT,
                format TEXT,
                created_by TEXT,
                session_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Vulnerabilities table for event triggers
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                target TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                description TEXT,
                status TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}", exc_info=True)
    finally:
        if conn:
            conn.close()

init_database()

class PlatformTools:
    """Handle platform-specific operations and commands"""
    
    def __init__(self, logger):
        self.logger = logger
        self.platform = platform.system().lower()
        self.is_windows = self.platform == 'windows'
        self.is_linux = self.platform == 'linux'
        self.is_macos = self.platform == 'darwin'
        
        # Check for available tools
        self.has_git = self._check_command('git --version')
        self.has_docker = self._check_command('docker --version')
        self.has_python = self._check_command('python --version')
        
        # Define platform-specific command templates
        self._init_command_templates()
    
    def _check_command(self, cmd: str) -> bool:
        """Check if a command is available on the system"""
        try:
            if self.is_windows:
                subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
            else:
                subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _init_command_templates(self):
        """Initialize platform-specific command templates"""
        self.commands = {
            # File operations
            'list_dir': 'dir' if self.is_windows else 'ls -la',
            'make_dir': 'mkdir',
            'remove_dir': 'rmdir /s /q' if self.is_windows else 'rm -rf',
            'copy_file': 'copy' if self.is_windows else 'cp',
            'move_file': 'move' if self.is_windows else 'mv',
            'touch_file': 'echo.>' if self.is_windows else 'touch',
            
            # Network tools
            'ping': 'ping -n 4' if self.is_windows else 'ping -c 4',
            'traceroute': 'tracert' if self.is_windows else 'traceroute',
            'ip_config': 'ipconfig' if self.is_windows else 'ifconfig',
            'dns_lookup': 'nslookup',
            'whois': 'whois',
            
            # System tools
            'processes': 'tasklist' if self.is_windows else 'ps aux',
            'kill_process': 'taskkill /F /PID' if self.is_windows else 'kill -9',
            
            # Git commands
            'git_clone': 'git clone',
            'git_pull': 'git pull',
            'git_status': 'git status',
            'git_commit': 'git commit -m',
            
            # Package management
            'install_pkg': 'pip install' if self.has_python else 
                          ('npm install' if self._check_command('npm -v') else None),
        }
    
    def execute_command(self, cmd: str) -> Tuple[str, int]:
        """Execute a command and return its output and exit code"""
        self.logger.info(f"Executing command: {cmd}")
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True,
                encoding='utf-8',
                errors='replace',
                check=True # Raise CalledProcessError for non-zero exit codes
            )
            self.logger.info(f"Command executed successfully. Exit Code: {result.returncode}")
            return result.stdout + result.stderr, result.returncode
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed with exit code {e.returncode}: {e.cmd}", exc_info=True)
            return e.stdout + e.stderr, e.returncode
        except FileNotFoundError:
            self.logger.error(f"Command not found: {cmd.split()[0]}")
            return f"Error: Command not found: {cmd.split()[0]}", 1
        except Exception as e:
            self.logger.exception(f"Error executing command '{cmd}':")
            return f"An unexpected error occurred: {str(e)}", 1
    
    def get_command(self, cmd_type: str, *args) -> Optional[str]:
        """Get a platform-specific command with arguments"""
        cmd_template = self.commands.get(cmd_type)
        if not cmd_template:
            return None
            
        return f"{cmd_template} {' '.join(args)}"
    
    def clone_github_repo(self, url: str, target_dir: Optional[str] = None) -> Tuple[str, int]:
        """Clone a GitHub repository"""
        if not self.has_git:
            return "Git is not installed on this system.", 1
            
        # Validate GitHub URL
        if not re.match(r'^https?://github\.com/[\w-]+/[\w.-]+(\.git)?$', url):
            return "Invalid GitHub URL. Please provide a valid GitHub repository URL.", 1
            
        cmd = f"git clone {url}"
        if target_dir:
            # Create target directory if it doesn't exist
            os.makedirs(target_dir, exist_ok=True)
            cmd += f" {target_dir}"
            
        return self.execute_command(cmd)
    
    def get_platform_info(self) -> Dict[str, Any]:
        """Get detailed information about the current platform"""
        info = {
            'platform': self.platform,
            'is_windows': self.is_windows,
            'is_linux': self.is_linux, 
            'is_macos': self.is_macos,
            'python_version': platform.python_version(),
            'tools': {
                'git': self.has_git,
                'docker': self.has_docker,
                'python': self.has_python
            },
            'system': {
                'os': platform.platform(),
                'processor': platform.processor(),
                'architecture': platform.architecture()[0]
            }
        }
        return info

# Available AI models from OpenRouter
AVAILABLE_AI_MODELS = [
    {
        'id': 'openai/gpt-4-turbo',
        'name': 'GPT-4 Turbo',
        'provider': 'OpenAI',
        'description': 'Latest GPT-4 model with enhanced capabilities'
    },
    {
        'id': 'openai/gpt-3.5-turbo',
        'name': 'GPT-3.5 Turbo',
        'provider': 'OpenAI',
        'description': 'Fast and efficient general purpose model'
    },
    {
        'id': 'anthropic/claude-3-opus',
        'name': 'Claude 3 Opus',
        'provider': 'Anthropic',
        'description': 'Most powerful Claude model with advanced reasoning'
    },
    {
        'id': 'anthropic/claude-3-sonnet',
        'name': 'Claude 3 Sonnet',
        'provider': 'Anthropic',
        'description': 'Balanced Claude model for most tasks'
    },
    {
        'id': 'google/gemini-pro',
        'name': 'Gemini Pro',
        'provider': 'Google',
        'description': "Google's advanced multi-modal model"
    },
    {
        'id': 'meta-llama/llama-3-70b-instruct',
        'name': 'Llama 3 70B',
        'provider': 'Meta',
        'description': 'Most powerful open source model'
    }
]

class EthicalHackingTools:
    """Comprehensive toolkit for ethical hacking operations"""
    
    CUSTOM_TOOLS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'custom_tools.json')

    def __init__(self, platform_tools):
        self.platform = platform_tools
        self.tools_db = self._initialize_tools_database()
        self.exploits_db = self._initialize_exploits_database()
        self.report_templates = self._initialize_report_templates()
        self._load_custom_tools() # Load custom tools on initialization

    def _save_custom_tools(self):
        """Saves the current custom tools to a JSON file."""
        try:
            with open(self.CUSTOM_TOOLS_FILE, 'w') as f:
                json.dump(self.tools_db, f, indent=4)
            self.platform.logger.info(f"Custom tools saved to {self.CUSTOM_TOOLS_FILE}")
        except Exception as e:
            self.platform.logger.error(f"Error saving custom tools: {e}", exc_info=True)

    def _load_custom_tools(self):
        """Loads custom tools from a JSON file and merges them with the default tools."""
        if os.path.exists(self.CUSTOM_TOOLS_FILE):
            try:
                with open(self.CUSTOM_TOOLS_FILE, 'r') as f:
                    custom_data = json.load(f)
                self.tools_db.update(custom_data) # Merge custom tools with default ones
                self.platform.logger.info(f"Custom tools loaded from {self.CUSTOM_TOOLS_FILE}")
            except Exception as e:
                self.platform.logger.error(f"Error loading custom tools: {e}", exc_info=True)
        else:
            self.platform.logger.info(f"Custom tools file not found: {self.CUSTOM_TOOLS_FILE}. Creating default.")
            self._save_custom_tools() # Create an empty file if it doesn't exist
        
    def _initialize_tools_database(self):
        """Initialize database of ethical hacking tools with their commands and availability"""
        self.platform.logger.info("Initializing tools database.")
        tools_db = {
            # Reconnaissance
            'nmap': {
                'category': 'reconnaissance',
                'description': 'Network mapper for port scanning and service detection - The ultimate network discovery tool',
                'install_cmd': {
                    'windows': 'winget install nmap',
                    'linux': 'apt-get install nmap',
                    'darwin': 'brew install nmap'
                },
                'check_cmd': 'nmap --version',
                'examples': [
                    # Basic scans
                    'nmap <target>',                    # Basic scan
                    'nmap -sS <target>',                # SYN scan (stealth)
                    'nmap -sT <target>',                # TCP connect scan
                    'nmap -sU <target>',                # UDP scan
                    
                    # Host discovery
                    'nmap -sn <target>',                # Ping scan (no port scan)
                    'nmap -Pn <target>',                # Skip ping, assume host is up
                    'nmap -PS22-25,80 <target>',       # TCP SYN ping on specific ports
                    'nmap -PE <target>',                # ICMP echo ping
                    
                    # Port scanning
                    'nmap -p80 <target>',               # Scan specific port
                    'nmap -p20-23 <target>',            # Scan port range
                    'nmap -p80,443,8080 <target>',      # Scan multiple specific ports
                    'nmap -p- <target>',                # Scan ALL ports (1-65535)
                    'nmap --top-ports 1000 <target>',   # Scan top 1000 most common ports
                    'nmap -p http,https,ssh <target>',  # Scan by service name
                    
                    # Advanced scans
                    'nmap -sV <target>',                # Version detection
                    'nmap -O <target>',                 # OS detection
                    'nmap -A <target>',                 # Aggressive scan (OS, version, scripts, traceroute)
                    'nmap -sC <target>',                # Default NSE scripts
                    'nmap --script vuln <target>',      # Vulnerability scanning scripts
                    'nmap --script http-enum <target>', # HTTP enumeration
                    
                    # Target specification
                    'nmap 192.168.1.1',                # Single IP
                    'nmap 192.168.1.0/24',             # CIDR subnet
                    'nmap 192.168.1.1-100',            # IP range
                    'nmap -iL hosts.txt',               # Targets from file
                    'nmap scanme.nmap.org',             # Domain name
                    
                    # Timing and performance
                    'nmap -T4 <target>',                # Aggressive timing
                    'nmap -T1 <target>',                # Slow/sneaky timing
                    'nmap --min-rate 100 <target>',     # Minimum packet rate
                    
                    # Output formats
                    'nmap -oN scan.txt <target>',       # Normal output
                    'nmap -oX scan.xml <target>',       # XML output
                    'nmap -oG scan.gnmap <target>',     # Grepable output
                    'nmap -oA scan_all <target>',       # All output formats
                    
                    # Common combinations
                    'nmap -sS -sV -O <target>',         # SYN scan with version and OS detection
                    'nmap -A -T4 <target>',             # Fast aggressive scan
                    'nmap -sS -sU -T4 --top-ports 1000 <target>',  # Both TCP and UDP top ports
                    'nmap -p- -sV -T4 <target>',        # Full port scan with version detection
                    'nmap --script http-* <target>',    # All HTTP scripts
                    'nmap -sV --script vuln -T4 <target>',  # Version detection with vulnerability scripts
                ]
            },
            'masscan': {
                'category': 'reconnaissance',
                'description': 'Fast port scanner',
                'install_cmd': {
                    'windows': 'git clone https://github.com/robertdavidgraham/masscan',
                    'linux': 'apt-get install masscan',
                    'darwin': 'brew install masscan'
                },
                'check_cmd': 'masscan --version',
                'examples': [
                    'masscan -p1-65535 \u003ctarget\u003e --rate=1000'
                ]
            },
            'amass': {
                'category': 'reconnaissance',
                'description': 'Network mapping of attack surfaces and external asset discovery',
                'install_cmd': {
                    'windows': 'go install -v github.com/owasp-amass/amass/v3/...',
                    'linux': 'apt-get install amass',
                    'darwin': 'brew install amass'
                },
                'check_cmd': 'amass -version',
                'examples': [
                    'amass enum -d \u003cdomain\u003e',
                    'amass intel -d \u003cdomain\u003e'
                ]
            },
            'hydra': {
                'category': 'password',
                'description': 'Network logon cracker which supports many different services',
                'install_cmd': {
                    'windows': 'winget install hydra',
                    'linux': 'apt-get install hydra',
                    'darwin': 'brew install hydra'
                },
                'check_cmd': 'hydra -h',
                'examples': [
                    'hydra -l admin -P passlist.txt ftp://\u003ctarget\u003e'
                ]
            },
            'metasploit': {
                'category': 'exploitation',
                'description': 'Advanced open-source platform for developing, testing, and executing exploits',
                'install_cmd': {
                    'windows': 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.bat > msfinstall.bat && msfinstall.bat',
                    'linux': 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall',
                    'darwin': 'brew install metasploit'
                },
                'check_cmd': 'msfconsole -v',
                'examples': [
                    'msfconsole',
                    'msfvenom -p windows/meterpreter/reverse_tcp LHOST=\u003cIP\u003e LPORT=\u003cPORT\u003e -f exe > payload.exe'
                ]
            },
            
            # Web Application Testing
            'nikto': {
                'category': 'web',
                'description': 'Web server scanner for vulnerabilities',
                'install_cmd': {
                    'windows': 'git clone https://github.com/sullo/nikto',
                    'linux': 'apt-get install nikto',
                    'darwin': 'brew install nikto'
                },
                'check_cmd': 'nikto -Version',
                'examples': [
                    'nikto -h <target>'
                ]
            },
            'sqlmap': {
                'category': 'web',
                'description': 'Automatic SQL injection and database takeover tool',
                'install_cmd': {
                    'windows': 'git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git',
                    'linux': 'apt-get install sqlmap',
                    'darwin': 'brew install sqlmap'
                },
                'check_cmd': 'sqlmap --version',
                'examples': [
                    'sqlmap -u "<url>" --dbs',
                    'sqlmap -u "<url>" -p <parameter>'
                ]
            },
            'gobuster': {
                'category': 'web',
                'description': 'Directory/file & DNS busting tool',
                'install_cmd': {
                    'windows': 'go install github.com/OJ/gobuster/v3@latest',
                    'linux': 'apt-get install gobuster',
                    'darwin': 'brew install gobuster'
                },
                'check_cmd': 'gobuster --version',
                'examples': [
                    'gobuster dir -u <url> -w <wordlist>',
                    'gobuster dns -d <domain> -w <wordlist>'
                ]
            },
            
            # Vulnerability Scanning
            'openvas': {
                'category': 'vulnerability',
                'description': 'Open vulnerability assessment scanner',
                'install_cmd': {
                    'windows': 'docker pull greenbone/openvas',
                    'linux': 'apt-get install openvas',
                    'darwin': 'brew install openvas'
                },
                'check_cmd': 'openvas --version',
                'examples': [
                    'openvas-start',
                    'gvm-cli --help'
                ]
            },
            
            # Password tools
            'hashcat': {
                'category': 'password',
                'description': 'Advanced password recovery tool',
                'install_cmd': {
                    'windows': 'winget install hashcat',
                    'linux': 'apt-get install hashcat',
                    'darwin': 'brew install hashcat'
                },
                'check_cmd': 'hashcat --version',
                'examples': [
                    'hashcat -m 0 -a 0 <hashfile> <wordlist>',
                    'hashcat -m 1000 -a 3 <hashfile> ?a?a?a?a?a?a'
                ]
            },
            'john': {
                'category': 'password',
                'description': 'John the Ripper password cracker',
                'install_cmd': {
                    'windows': 'winget install johntheripper',
                    'linux': 'apt-get install john',
                    'darwin': 'brew install john'
                },
                'check_cmd': 'john --version',
                'examples': [
                    'john --wordlist=<wordlist> <hashfile>',
                    'john --show <hashfile>'
                ]
            },
            
            # Wireless tools
            'aircrack-ng': {
                'category': 'wireless',
                'description': 'Complete suite for wireless network security assessment',
                'install_cmd': {
                    'windows': 'winget install aircrack-ng',
                    'linux': 'apt-get install aircrack-ng',
                    'darwin': 'brew install aircrack-ng'
                },
                'check_cmd': 'aircrack-ng --help',
                'examples': [
                    'airmon-ng start <interface>',
                    'airodump-ng <interface>',
                    'aireplay-ng -0 1 -a <bssid> -c <station> <interface>',
                    'aircrack-ng -w <wordlist> <capture file>'
                ]
            },
            
            # Exploitation
            'metasploit': {
                'category': 'exploitation',
                'description': 'Advanced open-source platform for developing, testing, and executing exploits',
                'install_cmd': {
                    'windows': 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.bat > msfinstall.bat && msfinstall.bat',
                    'linux': 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall',
                    'darwin': 'brew install metasploit'
                },
                'check_cmd': 'msfconsole -v',
                'examples': [
                    'msfconsole',
                    'msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > payload.exe'
                ]
            },
            
            # Social Engineering
            'social-engineer-toolkit': {
                'category': 'social',
                'description': 'Social Engineering Toolkit (SET)',
                'install_cmd': {
                    'windows': 'git clone https://github.com/trustedsec/social-engineer-toolkit',
                    'linux': 'apt-get install set',
                    'darwin': 'git clone https://github.com/trustedsec/social-engineer-toolkit'
                },
                'check_cmd': 'setoolkit --help',
                'examples': [
                    'setoolkit'
                ]
            },
            
            # OSINT
            'maltego': {
                'category': 'osint',
                'description': 'Open source intelligence and forensics application',
                'install_cmd': {
                    'windows': 'winget install maltego',
                    'linux': 'apt-get install maltego',
                    'darwin': 'brew cask install maltego'
                },
                'check_cmd': 'maltego --version',
                'examples': [
                    'maltego'
                ]
            },
            'theHarvester': {
                'category': 'osint',
                'description': 'E-mail, subdomain and name harvester',
                'install_cmd': {
                    'windows': 'git clone https://github.com/laramies/theHarvester',
                    'linux': 'apt-get install theharvester',
                    'darwin': 'brew install theharvester'
                },
                'check_cmd': 'theharvester -h',
                'examples': [
                    'theharvester -d <domain> -l 500 -b all'
                ]
            },
            
            # Forensics
            'volatility': {
                'category': 'forensics',
                'description': 'Memory forensics framework',
                'install_cmd': {
                    'windows': 'pip install volatility3',
                    'linux': 'pip install volatility3',
                    'darwin': 'pip install volatility3'
                },
                'check_cmd': 'vol -h',
                'examples': [
                    'vol -f <memory dump> windows.pslist',
                    'vol -f <memory dump> windows.netscan'
                ]
            },
            
            # Misc
            'wireshark': {
                'category': 'network',
                'description': 'Network protocol analyzer',
                'install_cmd': {
                    'windows': 'winget install wireshark',
                    'linux': 'apt-get install wireshark',
                    'darwin': 'brew install --cask wireshark'
                },
                'check_cmd': 'wireshark --version',
                'examples': [
                    'wireshark -i <interface>',
                    'tshark -i <interface> -Y "http"'
                ]
            },
            'burpsuite': {
                'category': 'web',
                'description': 'Web vulnerability scanner and proxy',
                'install_cmd': {
                    'windows': 'winget install burpsuite-community',
                    'linux': 'apt-get install burpsuite',
                    'darwin': 'brew install --cask burp-suite'
                },
                'check_cmd': 'java -jar burpsuite.jar --version',
                'examples': [
                    'burpsuite'
                ]
            },
            
            # Additional Comprehensive Tools
            'dirb': {
                'category': 'web',
                'description': 'Web content scanner',
                'install_cmd': {
                    'windows': 'git clone https://github.com/v0re/dirb',
                    'linux': 'apt-get install dirb',
                    'darwin': 'brew install dirb'
                },
                'check_cmd': 'dirb',
                'examples': [
                    'dirb http://target/',
                    'dirb http://target/ /usr/share/dirb/wordlists/common.txt'
                ]
            },
            'wpscan': {
                'category': 'web',
                'description': 'WordPress security scanner',
                'install_cmd': {
                    'windows': 'gem install wpscan',
                    'linux': 'apt-get install wpscan',
                    'darwin': 'gem install wpscan'
                },
                'check_cmd': 'wpscan --version',
                'examples': [
                    'wpscan --url http://target/',
                    'wpscan --url http://target/ --enumerate u'
                ]
            },
            'recon-ng': {
                'category': 'osint',
                'description': 'Full-featured reconnaissance framework',
                'install_cmd': {
                    'windows': 'git clone https://github.com/lanmaster53/recon-ng',
                    'linux': 'apt-get install recon-ng',
                    'darwin': 'pip install recon-ng'
                },
                'check_cmd': 'recon-ng --version',
                'examples': [
                    'recon-ng -w workspace_name',
                    'recon-ng -r /path/to/resource.rc'
                ]
            },
            'enum4linux': {
                'category': 'reconnaissance',
                'description': 'Linux/Unix enumeration tool for SMB hosts',
                'install_cmd': {
                    'windows': 'git clone https://github.com/CiscoCXSecurity/enum4linux-ng',
                    'linux': 'apt-get install enum4linux',
                    'darwin': 'brew install enum4linux'
                },
                'check_cmd': 'enum4linux -h',
                'examples': [
                    'enum4linux target_ip',
                    'enum4linux -a target_ip'
                ]
            },
            'fierce': {
                'category': 'reconnaissance',
                'description': 'Domain scanner',
                'install_cmd': {
                    'windows': 'pip install fierce',
                    'linux': 'apt-get install fierce',
                    'darwin': 'pip install fierce'
                },
                'check_cmd': 'fierce --version',
                'examples': [
                    'fierce --domain example.com',
                    'fierce --domain example.com --subdomains accounts admin'
                ]
            },
            'subfinder': {
                'category': 'reconnaissance',
                'description': 'Subdomain discovery tool',
                'install_cmd': {
                    'windows': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
                    'linux': 'apt-get install subfinder',
                    'darwin': 'brew install subfinder'
                },
                'check_cmd': 'subfinder -version',
                'examples': [
                    'subfinder -d example.com',
                    'subfinder -d example.com -o results.txt'
                ]
            },
            'nuclei': {
                'category': 'vulnerability',
                'description': 'Fast vulnerability scanner based on templates',
                'install_cmd': {
                    'windows': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
                    'linux': 'apt-get install nuclei',
                    'darwin': 'brew install nuclei'
                },
                'check_cmd': 'nuclei -version',
                'examples': [
                    'nuclei -u http://target/',
                    'nuclei -l urls.txt -t /path/to/templates/'
                ]
            },
            'ffuf': {
                'category': 'web',
                'description': 'Fast web fuzzer written in Go',
                'install_cmd': {
                    'windows': 'go install github.com/ffuf/ffuf@latest',
                    'linux': 'apt-get install ffuf',
                    'darwin': 'brew install ffuf'
                },
                'check_cmd': 'ffuf -V',
                'examples': [
                    'ffuf -w wordlist.txt -u http://target/FUZZ',
                    'ffuf -w wordlist.txt -u http://target/ -H "Host: FUZZ.target.com"'
                ]
            },
            'crackmapexec': {
                'category': 'exploitation',
                'description': 'Network service exploitation tool',
                'install_cmd': {
                    'windows': 'pip install crackmapexec',
                    'linux': 'apt-get install crackmapexec',
                    'darwin': 'pip install crackmapexec'
                },
                'check_cmd': 'crackmapexec --version',
                'examples': [
                    'crackmapexec smb target_ip',
                    'crackmapexec smb target_ip -u username -p password'
                ]
            },
            'impacket': {
                'category': 'exploitation',
                'description': 'Collection of Python classes for working with network protocols',
                'install_cmd': {
                    'windows': 'pip install impacket',
                    'linux': 'apt-get install impacket-scripts',
                    'darwin': 'pip install impacket'
                },
                'check_cmd': 'impacket-smbserver -h',
                'examples': [
                    'impacket-smbserver share /path/to/share',
                    'impacket-secretsdump domain/user:password@target'
                ]
            },
            
            # AI-Enhanced Tools
            'reconai': {
                'category': 'ai',
                'description': 'AI-powered reconnaissance combining OSINT with machine learning',
                'install_cmd': {
                    'windows': 'pip install openai requests',
                    'linux': 'pip install openai requests',
                    'darwin': 'pip install openai requests'
                },
                'check_cmd': 'python -c "import openai"',
                'examples': [
                    'python reconai.py --domain example.com',
                    'python reconai.py --target 192.168.1.1 --ai-analysis'
                ]
            },
            'xploitgpt': {
                'category': 'ai',
                'description': 'AI-assisted exploit writing and payload generation',
                'install_cmd': {
                    'windows': 'pip install openai tiktoken',
                    'linux': 'pip install openai tiktoken',
                    'darwin': 'pip install openai tiktoken'
                },
                'check_cmd': 'python -c "import openai"',
                'examples': [
                    'xploitgpt --generate-payload windows/x64',
                    'xploitgpt --analyze-binary target.exe'
                ]
            },
            'hackerai': {
                'category': 'ai',
                'description': 'AI-powered code review and vulnerability analysis',
                'install_cmd': {
                    'windows': 'pip install openai ast-grep',
                    'linux': 'pip install openai ast-grep',
                    'darwin': 'pip install openai ast-grep'
                },
                'check_cmd': 'python -c "import openai"',
                'examples': [
                    'hackerai --scan-code /path/to/source',
                    'hackerai --analyze-api-endpoints target.com'
                ]
            },
            'microsoft-security-copilot': {
                'category': 'ai',
                'description': 'AI assistant for incident response and security operations',
                'install_cmd': {
                    'windows': 'Available through Microsoft Security Center',
                    'linux': 'Available through Microsoft Security Center',
                    'darwin': 'Available through Microsoft Security Center'
                },
                'check_cmd': 'Available as cloud service',
                'examples': [
                    'Investigate security alert using AI analysis',
                    'Generate KQL queries for threat hunting'
                ]
            },
            
            # Modern Network Discovery
            'zmap': {
                'category': 'reconnaissance',
                'description': 'Internet-wide network scanner for research',
                'install_cmd': {
                    'windows': 'git clone https://github.com/zmap/zmap && make',
                    'linux': 'apt-get install zmap',
                    'darwin': 'brew install zmap'
                },
                'check_cmd': 'zmap --version',
                'examples': [
                    'zmap -p 80 0.0.0.0/0',
                    'zmap -p 443 10.0.0.0/8 -o results.csv'
                ]
            },
            'shodan-cli': {
                'category': 'osint',
                'description': 'Command-line interface for Shodan search engine',
                'install_cmd': {
                    'windows': 'pip install shodan',
                    'linux': 'pip install shodan',
                    'darwin': 'pip install shodan'
                },
                'check_cmd': 'shodan --version',
                'examples': [
                    'shodan search apache',
                    'shodan host 8.8.8.8'
                ]
            },
            
            # Advanced Vulnerability Scanners
            'nuclei': {
                'category': 'vulnerability',
                'description': 'Fast vulnerability scanner with community templates',
                'install_cmd': {
                    'windows': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
                    'linux': 'apt-get install nuclei',
                    'darwin': 'brew install nuclei'
                },
                'check_cmd': 'nuclei -version',
                'examples': [
                    'nuclei -u https://example.com',
                    'nuclei -l urls.txt -t cves/'
                ]
            },
            'naabu': {
                'category': 'reconnaissance',
                'description': 'Fast port scanner with SYN/CONNECT scan support',
                'install_cmd': {
                    'windows': 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
                    'linux': 'apt-get install naabu',
                    'darwin': 'brew install naabu'
                },
                'check_cmd': 'naabu -version',
                'examples': [
                    'naabu -host example.com',
                    'naabu -list hosts.txt -top-ports 1000'
                ]
            },
            
            # Modern Web Testing
            'ffuf': {
                'category': 'web',
                'description': 'Fast web fuzzer written in Go',
                'install_cmd': {
                    'windows': 'go install github.com/ffuf/ffuf@latest',
                    'linux': 'apt-get install ffuf',
                    'darwin': 'brew install ffuf'
                },
                'check_cmd': 'ffuf -V',
                'examples': [
                    'ffuf -w wordlist.txt -u http://target/FUZZ',
                    'ffuf -w params.txt -u http://target -d "FUZZ=test" -X POST'
                ]
            },
            'gau': {
                'category': 'osint',
                'description': 'Get all URLs from various sources like Wayback Machine',
                'install_cmd': {
                    'windows': 'go install github.com/lc/gau/v2/cmd/gau@latest',
                    'linux': 'apt-get install gau',
                    'darwin': 'brew install gau'
                },
                'check_cmd': 'gau --version',
                'examples': [
                    'gau example.com',
                    'gau --subs example.com | grep -i admin'
                ]
            },
            'waybackurls': {
                'category': 'osint',
                'description': 'Fetch URLs from Wayback Machine for domains',
                'install_cmd': {
                    'windows': 'go install github.com/tomnomnom/waybackurls@latest',
                    'linux': 'apt-get install waybackurls',
                    'darwin': 'brew install waybackurls'
                },
                'check_cmd': 'waybackurls --help',
                'examples': [
                    'waybackurls example.com',
                    'waybackurls example.com | grep -i admin'
                ]
            },
            'httprobe': {
                'category': 'web',
                'description': 'Probe for working HTTP and HTTPS servers',
                'install_cmd': {
                    'windows': 'go install github.com/tomnomnom/httprobe@latest',
                    'linux': 'apt-get install httprobe',
                    'darwin': 'brew install httprobe'
                },
                'check_cmd': 'httprobe --help',
                'examples': [
                    'cat domains.txt | httprobe',
                    'subfinder -d example.com | httprobe -c 50'
                ]
            },
            
            # Advanced OSINT
            'spiderfoot': {
                'category': 'osint',
                'description': 'Automated OSINT for threat intelligence',
                'install_cmd': {
                    'windows': 'pip install spiderfoot',
                    'linux': 'apt-get install spiderfoot',
                    'darwin': 'pip install spiderfoot'
                },
                'check_cmd': 'sf.py --help',
                'examples': [
                    'sf.py -s example.com -t IP_ADDRESS',
                    'sf.py -s example.com -m sfp_shodan'
                ]
            },
            'osrframework': {
                'category': 'osint',
                'description': 'OSINT framework with multiple modules',
                'install_cmd': {
                    'windows': 'pip install osrframework',
                    'linux': 'pip install osrframework',
                    'darwin': 'pip install osrframework'
                },
                'check_cmd': 'usufy.py --help',
                'examples': [
                    'usufy.py -n john_doe',
                    'mailfy.py -n john.doe@example.com'
                ]
            },
            
            # Mobile Security
            'mobsf': {
                'category': 'mobile',
                'description': 'Mobile Security Framework for Android/iOS',
                'install_cmd': {
                    'windows': 'git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git',
                    'linux': 'git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git',
                    'darwin': 'git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git'
                },
                'check_cmd': 'python manage.py help',
                'examples': [
                    'python manage.py runserver',
                    'Upload APK/IPA file for analysis'
                ]
            },
            'frida': {
                'category': 'mobile',
                'description': 'Dynamic instrumentation toolkit',
                'install_cmd': {
                    'windows': 'pip install frida-tools',
                    'linux': 'pip install frida-tools',
                    'darwin': 'pip install frida-tools'
                },
                'check_cmd': 'frida --version',
                'examples': [
                    'frida -U -f com.example.app',
                    'frida -U com.example.app -l script.js'
                ]
            },
            
            # Cloud Security
            'cloudsploit': {
                'category': 'cloud',
                'description': 'Cloud security configuration scanner',
                'install_cmd': {
                    'windows': 'git clone https://github.com/aquasecurity/cloudsploit.git',
                    'linux': 'git clone https://github.com/aquasecurity/cloudsploit.git',
                    'darwin': 'git clone https://github.com/aquasecurity/cloudsploit.git'
                },
                'check_cmd': 'node index.js --help',
                'examples': [
                    'node index.js --cloud aws',
                    'node index.js --cloud azure --compliance'
                ]
            },
            'prowler': {
                'category': 'cloud',
                'description': 'AWS/Azure/GCP security assessment tool',
                'install_cmd': {
                    'windows': 'pip install prowler-cloud',
                    'linux': 'pip install prowler-cloud',
                    'darwin': 'pip install prowler-cloud'
                },
                'check_cmd': 'prowler --version',
                'examples': [
                    'prowler aws',
                    'prowler aws --services s3,ec2'
                ]
            },
            
            # Network Packet Analysis
            'tcpdump': {
                'category': 'network',
                'description': 'Command-line packet analyzer',
                'install_cmd': {
                    'windows': 'winget install tcpdump',
                    'linux': 'apt-get install tcpdump',
                    'darwin': 'brew install tcpdump'
                },
                'check_cmd': 'tcpdump --version',
                'examples': [
                    'tcpdump -i eth0 port 80',
                    'tcpdump -i any -w capture.pcap'
                ]
            },
            'tshark': {
                'category': 'network',
                'description': 'Terminal-based Wireshark',
                'install_cmd': {
                    'windows': 'winget install wireshark',
                    'linux': 'apt-get install tshark',
                    'darwin': 'brew install wireshark'
                },
                'check_cmd': 'tshark --version',
                'examples': [
                    'tshark -i eth0 -f "port 443"',
                    'tshark -r capture.pcap -Y "http.request"'
                ]
            },
            
            # Modern Exploitation
            'pwntools': {
                'category': 'exploitation',
                'description': 'CTF framework and exploit development library',
                'install_cmd': {
                    'windows': 'pip install pwntools',
                    'linux': 'pip install pwntools',
                    'darwin': 'pip install pwntools'
                },
                'check_cmd': 'python -c "import pwn"',
                'examples': [
                    'python -c "from pwn import *; print(p64(0x41414141))"',
                    'pwn template binary_name'
                ]
            },
            'empire': {
                'category': 'exploitation',
                'description': 'PowerShell and Python post-exploitation framework',
                'install_cmd': {
                    'windows': 'git clone https://github.com/EmpireProject/Empire.git',
                    'linux': 'git clone https://github.com/EmpireProject/Empire.git',
                    'darwin': 'git clone https://github.com/EmpireProject/Empire.git'
                },
                'check_cmd': './empire --help',
                'examples': [
                    './empire --rest',
                    'uselistener http'
                ]
            },
            
            # API Security Testing
            'postman': {
                'category': 'api',
                'description': 'API development and testing platform',
                'install_cmd': {
                    'windows': 'winget install Postman.Postman',
                    'linux': 'snap install postman',
                    'darwin': 'brew install --cask postman'
                },
                'check_cmd': 'postman --version',
                'examples': [
                    'Create API collection for testing',
                    'Run automated API security tests'
                ]
            },
            'insomnia': {
                'category': 'api',
                'description': 'REST API client for testing',
                'install_cmd': {
                    'windows': 'winget install Insomnia.Insomnia',
                    'linux': 'snap install insomnia',
                    'darwin': 'brew install --cask insomnia'
                },
                'check_cmd': 'insomnia --version',
                'examples': [
                    'Test REST API endpoints',
                    'Validate API authentication'
                ]
            },
            
            # GitHub Community Tools Integration
            'sentinelpot': {
                'category': 'honeypot',
                'description': 'Interactive honeypot to detect unauthorized access with Discord alerts',
                'install_cmd': {
                    'windows': 'git clone https://github.com/Goofisded/SentinelPot',
                    'linux': 'git clone https://github.com/Goofisded/SentinelPot',
                    'darwin': 'git clone https://github.com/Goofisded/SentinelPot'
                },
                'check_cmd': 'python -c "import socket"',
                'examples': [
                    'python sentinelpot.py --port 22',
                    'python sentinelpot.py --webhook https://discord.com/api/webhooks/...'
                ]
            },
            'reconhound': {
                'category': 'reconnaissance',
                'description': 'Web reconnaissance tool for subdomain enumeration and fuzzing',
                'install_cmd': {
                    'windows': 'git clone https://github.com/s-r-e-e-r-a-j/ReconHound',
                    'linux': 'git clone https://github.com/s-r-e-e-r-a-j/ReconHound',
                    'darwin': 'git clone https://github.com/s-r-e-e-r-a-j/ReconHound'
                },
                'check_cmd': 'python -c "import requests"',
                'examples': [
                    'python reconhound.py -d example.com',
                    'python reconhound.py -d example.com -t 50'
                ]
            },
            'ziprarhunter': {
                'category': 'password',
                'description': 'Password cracker for ZIP and RAR archives using wordlists',
                'install_cmd': {
                    'windows': 'git clone https://github.com/fromnervok82/ZipRarHunter',
                    'linux': 'git clone https://github.com/fromnervok82/ZipRarHunter',
                    'darwin': 'git clone https://github.com/fromnervok82/ZipRarHunter'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python ziprarhunter.py -f archive.zip -w wordlist.txt',
                    'python ziprarhunter.py -f archive.rar -w rockyou.txt'
                ]
            },
            'network-vulnerability-scanner': {
                'category': 'vulnerability',
                'description': 'Lightweight Nmap automation tool for vulnerability scanning',
                'install_cmd': {
                    'windows': 'git clone https://github.com/ritik2898/Network-Vulnerability-Scanner',
                    'linux': 'git clone https://github.com/ritik2898/Network-Vulnerability-Scanner',
                    'darwin': 'git clone https://github.com/ritik2898/Network-Vulnerability-Scanner'
                },
                'check_cmd': 'nmap --version',
                'examples': [
                    'python scanner.py --target 192.168.1.1 --mode standard',
                    'python scanner.py --targets-file hosts.txt --mode aggressive'
                ]
            },
            'shadowstrike': {
                'category': 'exploitation',
                'description': 'Interactive SSH brute force simulation tool using Hydra',
                'install_cmd': {
                    'windows': 'git clone https://github.com/Artemis-solomon/ShadowStrike',
                    'linux': 'git clone https://github.com/Artemis-solomon/ShadowStrike',
                    'darwin': 'git clone https://github.com/Artemis-solomon/ShadowStrike'
                },
                'check_cmd': 'hydra -h',
                'examples': [
                    './shadowstrike.sh -t 192.168.1.100',
                    './shadowstrike.sh -t 192.168.1.100 -u admin -w passwords.txt'
                ]
            },
            'roguespeared': {
                'category': 'exploitation',
                'description': 'Generate polyglot files (valid WAV audio + executable Python)',
                'install_cmd': {
                    'windows': 'git clone https://github.com/KenB773/RogueSpeared',
                    'linux': 'git clone https://github.com/KenB773/RogueSpeared',
                    'darwin': 'git clone https://github.com/KenB773/RogueSpeared'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python roguespeared.py --payload payload.py --output malicious.wav',
                    'python roguespeared.py --encrypt --payload reverse_shell.py'
                ]
            },
            'darkshell': {
                'category': 'exploitation',
                'description': 'Web-based command and control (C2) framework',
                'install_cmd': {
                    'windows': 'git clone https://github.com/ELMERIKH/Darkshell',
                    'linux': 'git clone https://github.com/ELMERIKH/Darkshell',
                    'darwin': 'git clone https://github.com/ELMERIKH/Darkshell'
                },
                'check_cmd': 'node --version',
                'examples': [
                    'node server.js --port 8080',
                    'node server.js --ssl --cert cert.pem --key key.pem'
                ]
            },
            'port-scanner': {
                'category': 'reconnaissance',
                'description': 'Fast and efficient port scanner with asynchronous scanning',
                'install_cmd': {
                    'windows': 'git clone https://github.com/AdrianTomin/port-scanner',
                    'linux': 'git clone https://github.com/AdrianTomin/port-scanner',
                    'darwin': 'git clone https://github.com/AdrianTomin/port-scanner'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python scanner.py 192.168.1.1',
                    'python scanner.py 192.168.1.0/24 -p 80,443,22'
                ]
            },
            'ip-grabber': {
                'category': 'osint',
                'description': 'Educational IP grabber for social engineering awareness',
                'install_cmd': {
                    'windows': 'git clone https://github.com/Umar-Ahamed/ip-grabber',
                    'linux': 'git clone https://github.com/Umar-Ahamed/ip-grabber',
                    'darwin': 'git clone https://github.com/Umar-Ahamed/ip-grabber'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python ip_grabber.py --create-link',
                    'python ip_grabber.py --webhook https://discord.com/api/webhooks/...'
                ]
            },
            'dns-sniffer': {
                'category': 'network',
                'description': 'DNS queries and responses sniffer using Scapy',
                'install_cmd': {
                    'windows': 'git clone https://github.com/HalilDeniz/DNS-Sniffer',
                    'linux': 'git clone https://github.com/HalilDeniz/DNS-Sniffer',
                    'darwin': 'git clone https://github.com/HalilDeniz/DNS-Sniffer'
                },
                'check_cmd': 'python -c "import scapy"',
                'examples': [
                    'python dns_sniffer.py -i eth0',
                    'python dns_sniffer.py -i wlan0 --filter google.com'
                ]
            },
            'vulnerb': {
                'category': 'vulnerability',
                'description': 'Network exploration tool and security/port scanner',
                'install_cmd': {
                    'windows': 'git clone https://github.com/Abhijeet-Adani/Vulnerb',
                    'linux': 'git clone https://github.com/Abhijeet-Adani/Vulnerb',
                    'darwin': 'git clone https://github.com/Abhijeet-Adani/Vulnerb'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python vulnerb.py --target 192.168.1.1',
                    'python vulnerb.py --network 192.168.1.0/24 --scan-type comprehensive'
                ]
            },
            'dirgo': {
                'category': 'web',
                'description': 'Fast directory enumeration tool written in Go',
                'install_cmd': {
                    'windows': 'git clone https://github.com/tr41z/dirgo',
                    'linux': 'git clone https://github.com/tr41z/dirgo',
                    'darwin': 'git clone https://github.com/tr41z/dirgo'
                },
                'check_cmd': 'go version',
                'examples': [
                    './dirgo -u http://target.com -w wordlist.txt',
                    './dirgo -u http://target.com -w wordlist.txt -t 50'
                ]
            },
            'maskMyURL': {
                'category': 'social',
                'description': 'URL obfuscator using open redirects for phishing awareness',
                'install_cmd': {
                    'windows': 'git clone https://github.com/pacajuly/MaskMyURL-Url-Obfuscator',
                    'linux': 'git clone https://github.com/pacajuly/MaskMyURL-Url-Obfuscator',
                    'darwin': 'git clone https://github.com/pacajuly/MaskMyURL-Url-Obfuscator'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python maskmyurl.py --url https://evil.com --redirect google.com',
                    'python maskmyurl.py --url https://phishing.com --auth user:pass'
                ]
            },
            'sql-injection-testing': {
                'category': 'web',
                'description': 'SQL injection vulnerability testing application',
                'install_cmd': {
                    'windows': 'git clone https://github.com/LpCodes/SQL-Injection-Testing-app',
                    'linux': 'git clone https://github.com/LpCodes/SQL-Injection-Testing-app',
                    'darwin': 'git clone https://github.com/LpCodes/SQL-Injection-Testing-app'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python sql_tester.py --url http://target.com/page.php?id=1',
                    'python sql_tester.py --url http://target.com/login.php --post-data "user=admin&pass=test"'
                ]
            },
            'automated-reconator': {
                'category': 'reconnaissance',
                'description': 'Automated reconnaissance with CVE scanning and MITRE ATT&CK mapping',
                'install_cmd': {
                    'windows': 'git clone https://github.com/CyberDruid-Codes/Automated-Reconator',
                    'linux': 'git clone https://github.com/CyberDruid-Codes/Automated-Reconator',
                    'darwin': 'git clone https://github.com/CyberDruid-Codes/Automated-Reconator'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python reconator.py --target example.com --full-scan',
                    'python reconator.py --ip 192.168.1.1 --cve-scan'
                ]
            },
            'ftpbuster': {
                'category': 'password',
                'description': 'FTP, SFTP, and FTPS brute-forcing tool',
                'install_cmd': {
                    'windows': 'git clone https://github.com/s-r-e-e-r-a-j/FTPBuster',
                    'linux': 'git clone https://github.com/s-r-e-e-r-a-j/FTPBuster',
                    'darwin': 'git clone https://github.com/s-r-e-e-r-a-j/FTPBuster'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python ftpbuster.py -t 192.168.1.1 -u userlist.txt -p passlist.txt',
                    'python ftpbuster.py -t ftp.example.com -u admin -p passwords.txt --sftp'
                ]
            },
            'adminfinder': {
                'category': 'web',
                'description': 'Simple website admin panel finder',
                'install_cmd': {
                    'windows': 'git clone https://github.com/IanNarito/AdminFinder',
                    'linux': 'git clone https://github.com/IanNarito/AdminFinder',
                    'darwin': 'git clone https://github.com/IanNarito/AdminFinder'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python adminfinder.py -u http://target.com',
                    'python adminfinder.py -u http://target.com -t 20'
                ]
            },
            'hackfunction': {
                'category': 'toolkit',
                'description': 'Python toolkit for basic security checks and scans',
                'install_cmd': {
                    'windows': 'pip install hackfunction',
                    'linux': 'pip install hackfunction',
                    'darwin': 'pip install hackfunction'
                },
                'check_cmd': 'python -c "import hackfunction"',
                'examples': [
                    'python -c "from hackfunction import port_scan; port_scan(\'192.168.1.1\')"',
                    'python -c "from hackfunction import vulnerability_check; vulnerability_check(\'target.com\')"'
                ]
            },
            'sitescraper': {
                'category': 'web',
                'description': 'Website cloning tool for educational purposes',
                'install_cmd': {
                    'windows': 'git clone https://github.com/s-r-e-e-r-a-j/SiteScraper',
                    'linux': 'git clone https://github.com/s-r-e-e-r-a-j/SiteScraper',
                    'darwin': 'git clone https://github.com/s-r-e-e-r-a-j/SiteScraper'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python sitescraper.py --url http://example.com',
                    'python sitescraper.py --url http://example.com --output-dir cloned_site'
                ]
            },
            'subgram': {
                'category': 'reconnaissance',
                'description': 'Automated subdomain scanner with Telegram updates',
                'install_cmd': {
                    'windows': 'git clone https://github.com/TheFellowHacker/subgram',
                    'linux': 'git clone https://github.com/TheFellowHacker/subgram',
                    'darwin': 'git clone https://github.com/TheFellowHacker/subgram'
                },
                'check_cmd': 'subfinder -version',
                'examples': [
                    './subgram.sh -d example.com',
                    './subgram.sh -d example.com -t telegram_bot_token -c chat_id'
                ]
            },
            'scalpy': {
                'category': 'ai',
                'description': 'AI-powered network discovery and security auditing tool',
                'install_cmd': {
                    'windows': 'git clone https://github.com/brightjonathan/SCALPY',
                    'linux': 'git clone https://github.com/brightjonathan/SCALPY',
                    'darwin': 'git clone https://github.com/brightjonathan/SCALPY'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python scalpy.py --target 192.168.1.0/24 --ai-analysis',
                    'python scalpy.py --target example.com --deep-scan'
                ]
            },
            'cve-2024-9166-scanner': {
                'category': 'vulnerability',
                'description': 'Scanner for CVE-2024-9166 vulnerability (critical RCE)',
                'install_cmd': {
                    'windows': 'git clone https://github.com/Andrysqui/CVE-2024-9166',
                    'linux': 'git clone https://github.com/Andrysqui/CVE-2024-9166',
                    'darwin': 'git clone https://github.com/Andrysqui/CVE-2024-9166'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python cve-2024-9166.py --target http://vulnerable-site.com',
                    'python cve-2024-9166.py --file targets.txt'
                ]
            },
            'domain8': {
                'category': 'reconnaissance',
                'description': 'Asynchronous domain enumeration tool',
                'install_cmd': {
                    'windows': 'git clone https://github.com/j4ke-exe/DOMAIN8',
                    'linux': 'git clone https://github.com/j4ke-exe/DOMAIN8',
                    'darwin': 'git clone https://github.com/j4ke-exe/DOMAIN8'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python domain8.py -d example.com',
                    'python domain8.py -d example.com -w custom_wordlist.txt'
                ]
            },
            'google-dorking-tool': {
                'category': 'osint',
                'description': 'Advanced Google Dorking tool for information gathering',
                'install_cmd': {
                    'windows': 'git clone https://github.com/sethysatyajit/Google-Dorking-Tool',
                    'linux': 'git clone https://github.com/sethysatyajit/Google-Dorking-Tool',
                    'darwin': 'git clone https://github.com/sethysatyajit/Google-Dorking-Tool'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'Open the web interface and use GUI for dorking',
                    'Create custom dorks for target domain'
                ]
            },
            'poisonit': {
                'category': 'network',
                'description': 'ARP Poisoning tool for network security testing',
                'install_cmd': {
                    'windows': 'git clone https://github.com/Kedar-Parikh/PoisonIt',
                    'linux': 'git clone https://github.com/Kedar-Parikh/PoisonIt',
                    'darwin': 'git clone https://github.com/Kedar-Parikh/PoisonIt'
                },
                'check_cmd': 'python -c "import scapy"',
                'examples': [
                    'python poisonit.py -t 192.168.1.100 -g 192.168.1.1',
                    'python poisonit.py -t 192.168.1.100 -g 192.168.1.1 -i eth0'
                ]
            },
            'ipscanner': {
                'category': 'osint',
                'description': 'IPv4/IPv6 address information gathering tool',
                'install_cmd': {
                    'windows': 'git clone https://github.com/kinhal/ipscanner',
                    'linux': 'git clone https://github.com/kinhal/ipscanner',
                    'darwin': 'git clone https://github.com/kinhal/ipscanner'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python ipscanner.py 8.8.8.8',
                    'python ipscanner.py 2001:4860:4860::8888'
                ]
            },
            'arp-active-scanner': {
                'category': 'network',
                'description': 'ARP-based network device discovery tool',
                'install_cmd': {
                    'windows': 'git clone https://github.com/ma1loc/arp_active_scanner',
                    'linux': 'git clone https://github.com/ma1loc/arp_active_scanner',
                    'darwin': 'git clone https://github.com/ma1loc/arp_active_scanner'
                },
                'check_cmd': 'python -c "import scapy"',
                'examples': [
                    'python arp_scanner.py 192.168.1.0/24',
                    'python arp_scanner.py -r 192.168.1.1-254'
                ]
            },
            'recon-tool': {
                'category': 'reconnaissance',
                'description': 'Python-based reconnaissance tool with CLI and GUI interfaces',
                'install_cmd': {
                    'windows': 'git clone https://github.com/mtalhattari/recon-tool',
                    'linux': 'git clone https://github.com/mtalhattari/recon-tool',
                    'darwin': 'git clone https://github.com/mtalhattari/recon-tool'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python recon_tool.py --target example.com --whois',
                    'python recon_tool.py --target example.com --full-recon'
                ]
            },
            'substaceus': {
                'category': 'reconnaissance',
                'description': 'High-performance subdomain scanner built in Rust',
                'install_cmd': {
                    'windows': 'git clone https://github.com/Fedekkc/Substaceus',
                    'linux': 'git clone https://github.com/Fedekkc/Substaceus',
                    'darwin': 'git clone https://github.com/Fedekkc/Substaceus'
                },
                'check_cmd': 'cargo --version',
                'examples': [
                    'cargo run -- -d example.com',
                    'cargo run -- -d example.com -w wordlist.txt -t 100'
                ]
            },
            'gobrute': {
                'category': 'password',
                'description': 'RESTful API brute-forcing tool in Go for ethical hacking',
                'install_cmd': {
                    'windows': 'git clone https://github.com/lunzai/gobrute',
                    'linux': 'git clone https://github.com/lunzai/gobrute',
                    'darwin': 'git clone https://github.com/lunzai/gobrute'
                },
                'check_cmd': 'go version',
                'examples': [
                    './gobrute -u http://target.com/login -U userlist.txt -P passlist.txt',
                    './gobrute -u http://target.com/api/login -m POST -d "username=USER&password=PASS"'
                ]
            },
            'xdorking': {
                'category': 'osint',
                'description': 'Google dorking tool for finding websites with specific vulnerabilities',
                'install_cmd': {
                    'windows': 'git clone https://github.com/Whomrx666/Xdorking',
                    'linux': 'git clone https://github.com/Whomrx666/Xdorking',
                    'darwin': 'git clone https://github.com/Whomrx666/Xdorking'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python xdorking.py',
                    'python xdorking.py --dork "inurl:admin" --pages 10'
                ]
            },
            'ip-tracker': {
                'category': 'osint',
                'description': 'IP address tracker with geographic information and mapping',
                'install_cmd': {
                    'windows': 'git clone https://github.com/CodeWave373/IP-Tracker',
                    'linux': 'git clone https://github.com/CodeWave373/IP-Tracker',
                    'darwin': 'git clone https://github.com/CodeWave373/IP-Tracker'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python ip_tracker.py 8.8.8.8',
                    'python ip_tracker.py --file ip_list.txt'
                ]
            },
            'sec-headers-check': {
                'category': 'web',
                'description': 'HTTP Security Headers Checker written in Go',
                'install_cmd': {
                    'windows': 'git clone https://github.com/had-nu/sec-headers-check',
                    'linux': 'git clone https://github.com/had-nu/sec-headers-check',
                    'darwin': 'git clone https://github.com/had-nu/sec-headers-check'
                },
                'check_cmd': 'go version',
                'examples': [
                    './sec-headers-check -u http://example.com',
                    './sec-headers-check -f urls.txt'
                ]
            },
            'ptoolkit': {
                'category': 'toolkit',
                'description': 'Super easy-to-use penetration testing toolkit',
                'install_cmd': {
                    'windows': 'git clone https://github.com/tp054538/ptoolkit',
                    'linux': 'git clone https://github.com/tp054538/ptoolkit',
                    'darwin': 'git clone https://github.com/tp054538/ptoolkit'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python ptoolkit.py',
                    'python ptoolkit.py --target 192.168.1.1'
                ]
            },
            'sql-exploiter': {
                'category': 'web',
                'description': 'SQL injection exploitation tool',
                'install_cmd': {
                    'windows': 'git clone https://github.com/tX-c0re/SQL-Exploiter',
                    'linux': 'git clone https://github.com/tX-c0re/SQL-Exploiter',
                    'darwin': 'git clone https://github.com/tX-c0re/SQL-Exploiter'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python sql_exploiter.py --url "http://target.com/page.php?id=1"',
                    'python sql_exploiter.py --url "http://target.com/login.php" --post'
                ]
            },
            'shdwhack': {
                'category': 'toolkit',
                'description': 'Comprehensive hacking toolkit with multiple attack vectors',
                'install_cmd': {
                    'windows': 'git clone https://github.com/nischal-sketch21/Shdwhack',
                    'linux': 'git clone https://github.com/nischal-sketch21/Shdwhack',
                    'darwin': 'git clone https://github.com/nischal-sketch21/Shdwhack'
                },
                'check_cmd': 'bash --version',
                'examples': [
                    './shdwhack.sh',
                    'bash shdwhack.sh --target 192.168.1.1'
                ]
            },
            'lewis': {
                'category': 'ai',
                'description': 'AI-powered cybersecurity intelligence platform',
                'install_cmd': {
                    'windows': 'git clone https://github.com/yashab-cyber/lewis',
                    'linux': 'git clone https://github.com/yashab-cyber/lewis',
                    'darwin': 'git clone https://github.com/yashab-cyber/lewis'
                },
                'check_cmd': 'python --version',
                'examples': [
                    'python lewis.py --analyze-target example.com',
                    'python lewis.py --ai-powered-recon 192.168.1.0/24'
                ]
            },
            'quicktrack': {
                'category': 'monitoring',
                'description': 'IP address monitoring tool for detecting ports and vulnerabilities',
                'install_cmd': {
                    'windows': 'git clone https://github.com/rajkanya2709/QuickTrack',
                    'linux': 'git clone https://github.com/rajkanya2709/QuickTrack',
                    'darwin': 'git clone https://github.com/rajkanya2709/QuickTrack'
                },
                'check_cmd': 'go version',
                'examples': [
                    './quicktrack -target 192.168.1.1',
                    './quicktrack -target 192.168.1.1 --continuous'
                ]
            }
        }
        return tools_db
    
    def _initialize_exploits_database(self):
        """Initialize exploits database sources"""
        self.platform.logger.info("Initializing exploits database.")
        return {
            'exploit-db': {
                'url': 'https://www.exploit-db.com',
                'search_url': 'https://www.exploit-db.com/search?q=',
                'description': 'Offensive Security Exploit Database',
                'api_available': True
            },
            'vulners': {
                'url': 'https://vulners.com',
                'search_url': 'https://vulners.com/search?query=',
                'description': 'Vulnerability Database',
                'api_available': True
            },
            'cve': {
                'url': 'https://cve.mitre.org',
                'search_url': 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=',
                'description': 'Common Vulnerabilities and Exposures Database',
                'api_available': True
            },
            'rapid7': {
                'url': 'https://www.rapid7.com/db',
                'search_url': 'https://www.rapid7.com/db/?q=',
                'description': 'Rapid7 Vulnerability & Exploit Database',
                'api_available': True
            }
        }
    
    def _initialize_report_templates(self):
        """Initialize pentesting report templates"""
        self.platform.logger.info("Initializing report templates.")
        return {
            'standard': {
                'name': 'Standard Penetration Test Report',
                'sections': [
                    'Executive Summary',
                    'Methodology',
                    'Findings and Recommendations',
                    'Risk Assessment',
                    'Technical Details',
                    'Remediation Plan',
                    'Appendices'
                ],
                'format': ['docx', 'pdf', 'html']
            },
            'compliance': {
                'name': 'Compliance-Focused Report',
                'sections': [
                    'Executive Overview',
                    'Scope and Methodology',
                    'Compliance Status',
                    'Gap Analysis',
                    'Detailed Findings',
                    'Remediation Roadmap',
                    'Attestation of Testing'
                ],
                'format': ['docx', 'pdf']
            },
            'executive': {
                'name': 'Executive Brief',
                'sections': [
                    'Summary of Findings',
                    'Risk Assessment',
                    'Key Vulnerabilities',
                    'Strategic Recommendations',
                    'Budget Considerations'
                ],
                'format': ['docx', 'pdf', 'pptx']
            }
        }
    
    def check_tool_availability(self, tool_name):
        """Check if a specific tool is available on the system"""
        self.platform.logger.info(f"Checking availability for tool: {tool_name}")
        if tool_name not in self.tools_db:
            self.platform.logger.warning(f"Tool {tool_name} not found in database.")
            return {'available': False, 'error': 'Tool not in database'}
            
        tool_info = self.tools_db[tool_name]
        check_cmd = tool_info.get('check_cmd')
        
        if not check_cmd:
            self.platform.logger.warning(f"No check command defined for tool: {tool_name}")
            return {'available': False, 'error': 'No check command defined'}
        
        try:
            output, exit_code = self.platform.execute_command(check_cmd)
            if exit_code == 0:
                self.platform.logger.info(f"Tool {tool_name} is available. Version: {output.strip()}")
                return {'available': True, 'version': output.strip()}
            else:
                self.platform.logger.info(f"Tool {tool_name} is NOT available. Check command failed. Exit code: {exit_code}")
                return {'available': False, 'error': 'Tool check failed'}
        except Exception as e:
            self.platform.logger.error(f"Error checking tool availability for {tool_name}: {e}", exc_info=True)
            return {'available': False, 'error': str(e)}
    
    def get_tool_examples(self, tool_name):
        """Get examples for using a specific tool"""
        self.platform.logger.info(f"Getting examples for tool: {tool_name}")
        if tool_name not in self.tools_db:
            self.platform.logger.warning(f"Tool {tool_name} not found in database for examples.")
            return []
        
        return self.tools_db[tool_name].get('examples', [])
    
    def get_tool_categories(self):
        """Get all tool categories with their tools"""
        self.platform.logger.info("Getting all tool categories.")
        categories = {}
        
        for tool_name, tool_info in self.tools_db.items():
            category = tool_info.get('category', 'uncategorized')
            if category not in categories:
                categories[category] = []
            
            categories[category].append({
                'name': tool_name,
                'description': tool_info.get('description', '')
            })
        
        self.platform.logger.info(f"Found {len(categories)} tool categories.")
        return categories
    
    def get_installation_command(self, tool_name):
        """Get platform-specific installation command for a tool"""
        self.platform.logger.info(f"Getting installation command for tool: {tool_name}")
        if tool_name not in self.tools_db:
            self.platform.logger.warning(f"Tool {tool_name} not found in database for installation command.")
            return None
            
        tool_info = self.tools_db[tool_name]
        install_commands = tool_info.get('install_cmd', {})
        
        # Get the appropriate command for the current platform
        platform_key = 'windows' if self.platform.is_windows else ('darwin' if self.platform.is_macos else 'linux')
        command = install_commands.get(platform_key)
        if command:
            self.platform.logger.info(f"Found installation command for {tool_name} on {platform_key}: {command}")
        else:
            self.platform.logger.warning(f"No installation command found for {tool_name} on {platform_key}.")
        return command

    def add_custom_tool(self, tool_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adds a custom tool definition to the tools database.
        """
        tool_name = tool_data.get('name')
        if not tool_name:
            return {'success': False, 'error': 'Tool name is required.'}
        
        if tool_name in self.tools_db:
            return {'success': False, 'error': f'Tool {tool_name} already exists.'}

        self.tools_db[tool_name] = tool_data
        self._save_custom_tools() # Persist changes
        return {'success': True, 'message': f'Tool {tool_name} added successfully.'}

    def install_tool(self, tool_name: str) -> Dict[str, Any]:
        """Installs a specified ethical hacking tool.
        """
        install_cmd = self.get_installation_command(tool_name)
        if not install_cmd:
            return {'success': False, 'error': f'No installation command found for {tool_name} on this platform.'}

        self.platform.logger.info(f"Attempting to install {tool_name} with command: {install_cmd}")
        output, exit_code = self.platform.execute_command(install_cmd)

        if exit_code == 0:
            return {'success': True, 'message': f'{tool_name} installed successfully.', 'output': output}
        else:
            return {'success': False, 'error': f'Failed to install {tool_name}. Exit code: {exit_code}. Output: {output}'}

    def get_installed_tools(self) -> List[Dict[str, Any]]:
        """Returns a list of tools currently installed on the system.
        """
        installed_tools = []
        for tool_name in self.tools_db.keys():
            check_result = self.check_tool_availability(tool_name)
            if check_result['available']:
                installed_tools.append({'name': tool_name, 'version': check_result.get('version', 'Unknown')})
        return installed_tools

    def search_exploits(self, query, source='exploit-db'):
        """Search for exploits in specified database"""
        self.platform.logger.info(f"Searching exploits for query: '{query}' in source: {source}")
        if source not in self.exploits_db:
            self.platform.logger.warning(f"Unknown exploit database source: {source}")
            return {'error': 'Unknown exploit database source'}
            
        db_info = self.exploits_db[source]
        search_url = f"{db_info['search_url']}{query}"
        
        # For now, return the search URL - in a real implementation, we'd parse results
        self.platform.logger.info(f"Returning search URL for exploits: {search_url}")
        return {
            'query': query,
            'source': source,
            'source_name': db_info['description'],
            'search_url': search_url,
            'results': []
        }
    
    def generate_report_template(self, template_name='standard'):
        """Generate a penetration test report template"""
        self.platform.logger.info(f"Generating report template: {template_name}")
        if template_name not in self.report_templates:
            self.platform.logger.warning(f"Report template '{template_name}' not found.")
            return {'error': 'Unknown report template'}
            
        template = self.report_templates[template_name]
        
        # Generate a simple template structure - in reality, we'd create actual documents
        self.platform.logger.info(f"Report template {template_name} generated.")
        return {
            'name': template['name'],
            'sections': template['sections'],
            'available_formats': template['format']
        }

platform_tools = PlatformTools(logger)
# Initialize the StreamManager
stream_manager = StreamManager(socketio)

# Directory setup for uploads and reports
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
REPORT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# Scenarios API Routes
@app.route('/api/scenarios', methods=['GET'])
def get_scenarios() -> Response:
    """API endpoint to retrieve all available scenarios."""
    try:
        scenarios = scenario_manager.get_all_scenarios()
        logger.info("Fetched all scenarios.")
        return jsonify(scenarios)
    except Exception as e:
        logger.exception("Error fetching scenarios:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/scenarios/custom', methods=['POST'])
def create_custom_scenario() -> Response:
    """API endpoint to create a custom scenario (workflow)."""
    try:
        data = request.get_json()
        result = scenario_manager.create_workflow(data['name'], data['description'], data['steps'], data['triggers'], data['created_by'])
        logger.info(f"Created custom scenario: {data.get('name')}")
        return jsonify(result)
    except KeyError as ke:
        logger.error(f"API Error: Missing data for custom scenario creation: {ke}")
        return jsonify({'error': f'Missing data for custom scenario creation: {ke}'}), 400
    except Exception as e:
        logger.exception("Error creating custom scenario:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

# Tools API Routes
@app.route('/api/tools/check/<tool_name>', methods=['GET'])
def check_tool(tool_name: str) -> Response:
    """API endpoint to check the installation status of a tool."""
    try:
        result = tool_manager.check_tool_availability(tool_name)
        logger.info(f"Checked tool availability for {tool_name}. Result: {result.get('available')}")
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Error checking tool availability for {tool_name}:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/tools/install/<tool_name>', methods=['POST'])
def install_tool(tool_name: str) -> Response:
    """API endpoint to install a specified tool."""
    try:
        result = tool_manager.install_tool(tool_name)
        logger.info(f"Attempted to install tool {tool_name}. Success: {result.get('success')}")
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Error installing tool {tool_name}:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/tools/installed', methods=['GET'])
def get_installed_tools() -> Response:
    """API endpoint to retrieve a list of installed tools."""
    try:
        tools = tool_manager.get_installed_tools()
        logger.info("Fetched list of installed tools.")
        return jsonify(tools)
    except Exception as e:
        logger.exception("Error fetching installed tools:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/tools/categories', methods=['GET'])
def get_tool_categories() -> Response:
    """API endpoint to retrieve all tool categories."""
    try:
        categories = tool_manager.get_tool_categories()
        logger.info("Fetched tool categories.")
        return jsonify(categories)
    except Exception as e:
        logger.exception("Error fetching tool categories:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/tools/custom', methods=['POST'])
def add_custom_tool() -> Response:
    """API endpoint to add a custom tool definition."""
    try:
        data = request.get_json()
        result = tool_manager.add_custom_tool(data)
        logger.info(f"Added custom tool: {data.get('name')}. Success: {result.get('success')}")
        return jsonify(result)
    except Exception as e:
        logger.exception("Error adding custom tool:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

# Report API Routes
@app.route('/api/reports/templates', methods=['GET'])
def get_report_templates() -> Response:
    """API endpoint to retrieve available report templates."""
    try:
        templates = report_generator.get_templates()
        logger.info("Fetched report templates.")
        return jsonify(templates)
    except Exception as e:
        logger.exception("Error fetching report templates:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/reports/generate', methods=['POST'])
def generate_report() -> Response:
    """API endpoint to generate a new report."""
    try:
        data = request.get_json()
        result = report_generator.generate_report(data['template_name'], data['data'], data.get('format', 'html'))
        logger.info(f"Generated report for template {data.get('template_name')}. Result: {result.get('report_id')}")
        return jsonify(result)
    except KeyError as ke:
        logger.error(f"API Error: Missing data for report generation: {ke}")
        return jsonify({'error': f'Missing data for report generation: {ke}'}), 400
    except Exception as e:
        logger.exception("Error generating report:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/reports/download/<report_id>', methods=['GET'])
def download_report(report_id: str) -> Response:
    """API endpoint to download a generated report."""
    try:
        export_format = request.args.get('format', 'html') # Get format from query param
        result = report_generator.export_report(report_id, export_format)
        if result.get('error'):
            return jsonify({'error': result['error']}), 404

        report_path = result['path']
        filename = result['filename']

        logger.info(f"Attempting to download report {report_id} from {report_path}")
        return send_from_directory(
            os.path.dirname(report_path),
            os.path.basename(report_path),
            as_attachment=True,
            download_name=filename # Use download_name for correct filename in browser
        )
    except FileNotFoundError:
        logger.error(f"Report file not found for report_id: {report_id}")
        return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        logger.exception(f"Error downloading report {report_id}:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/reports/upload-evidence', methods=['POST'])
def upload_evidence() -> Response:
    """API endpoint to upload evidence files."""
    try:
        if 'files' not in request.files:
            logger.error("API Error: No files provided for evidence upload.")
            return jsonify({'error': 'No files provided'}), 400

        files = request.files.getlist('files')
        paths = []

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                evidence_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(evidence_path)
                paths.append(evidence_path)
                logger.info(f"Uploaded evidence file: {filename}")
            else:
                logger.warning(f"Attempted to upload disallowed file type: {file.filename}")
                return jsonify({'error': f'File type not allowed: {file.filename}'}), 400

        return jsonify({'paths': paths})
    except Exception as e:
        logger.exception("Error uploading evidence:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

# Vulnerability API Routes
@app.route('/api/vulnerability/cve/<cve_id>', methods=['GET'])
def get_cve_details(cve_id: str) -> Response:
    """API endpoint to retrieve details for a specific CVE."""
    try:
        details = vulnerability_enrichment.get_cve_details(cve_id)
        logger.info(f"Fetched CVE details for {cve_id}.")
        return jsonify(details)
    except Exception as e:
        logger.exception(f"Error fetching CVE details for {cve_id}:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/vulnerability/exploits/<cve_id>', methods=['GET'])
def get_exploits(cve_id: str) -> Response:
    """API endpoint to search for exploits related to a CVE."""
    try:
        exploits = vulnerability_enrichment.search__exploits(cve_id)
        logger.info(f"Searched exploits for {cve_id}.")
        return jsonify(exploits)
    except Exception as e:
        logger.exception(f"Error searching exploits for {cve_id}:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

# Execute command/step API
@app.route('/api/execute_step', methods=['POST'])
def execute_step() -> Response:
    """API endpoint to execute a single command or step."""
    try:
        data = request.get_json()
        command = data.get('command')
        target = data.get('target')

        if not command:
            logger.error("API Error: No command provided in /api/execute_step request.")
            return jsonify({'error': 'No command provided'}), 400

        # Replace placeholders in command
        command = command.replace('{target}', target)

        # Execute command and get output
        output, exit_code = platform_tools.execute_command(command)

        logger.info(f"Executed step command '{command}'. Exit Code: {exit_code}")
        return jsonify({
            'output': output,
            'exit_code': exit_code,
            'success': exit_code == 0
        })
    except Exception as e:
        logger.exception(f"Error executing step command '{command}':")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/process_command', methods=['POST'])
def process_command_api() -> Response:
    """API endpoint to process commands using the Ethical Hacking Assistant core logic."""
    try:
        data = request.get_json()
        mode = data.get('mode')
        command = data.get('command')

        if not mode or not command:
            logger.error("API Error: Mode or command missing in /api/process_command request.")
            return jsonify({'error': 'Mode and command are required'}), 400

        result = ethical_hacking_assistant.process_command(mode, command)
        logger.info(f"Processed command '{command}' in mode '{mode}'. Result: {result[:100]}...") # Log first 100 chars
        return jsonify({'result': result})
    except Exception as e:
        logger.exception(f"Error processing command '{command}' in mode '{mode}':") # Log full traceback
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

# Nmap Helper API Routes
@app.route('/api/nmap/suggest_command', methods=['POST'])
def nmap_suggest_command() -> Response:
    """API endpoint to get Nmap command suggestions based on target and purpose."""
    try:
        data = request.get_json()
        target = data.get('target')
        purpose = data.get('purpose', 'general')
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        suggestions = ethical_hacking_assistant.nmap_helper.suggest_scan_command(target, purpose)
        return jsonify(suggestions)
    except Exception as e:
        logger.exception("Error suggesting Nmap command:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/nmap/cheat_sheet', methods=['GET'])
def nmap_cheat_sheet() -> Response:
    """API endpoint to retrieve the complete Nmap cheat sheet."""
    try:
        cheat_sheet = ethical_hacking_assistant.nmap_helper.get_cheat_sheet()
        return jsonify(cheat_sheet)
    except Exception as e:
        logger.exception("Error getting Nmap cheat sheet:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

# OSCP Resources API Routes
@app.route('/api/oscp/methodology', methods=['GET'])
def oscp_methodology() -> Response:
    """API endpoint to retrieve the OSCP methodology framework."""
    try:
        methodology = ethical_hacking_assistant.oscp_resources.get_oscp_methodology()
        return jsonify(methodology)
    except Exception as e:
        logger.exception("Error getting OSCP methodology:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/oscp/buffer_overflow_guide', methods=['GET'])
def oscp_buffer_overflow_guide() -> Response:
    """API endpoint to retrieve the OSCP buffer overflow guide."""
    try:
        guide = ethical_hacking_assistant.oscp_resources.get_buffer_overflow_guide()
        return jsonify(guide)
    except Exception as e:
        logger.exception("Error getting buffer overflow guide:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/oscp/privilege_escalation_checks', methods=['GET'])
def oscp_privilege_escalation_checks() -> Response:
    """API endpoint to retrieve privilege escalation checks for a given OS."""
    try:
        checks = ethical_hacking_assistant.oscp_resources.get_privilege_escalation_checks()
        return jsonify(checks)
    except Exception as e:
        logger.exception("Error getting privilege escalation checks:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/oscp/active_directory_attacks', methods=['GET'])
def oscp_active_directory_attacks() -> Response:
    """API endpoint to retrieve Active Directory attack methodologies."""
    try:
        attacks = ethical_hacking_assistant.oscp_resources.get_active_directory_attacks()
        return jsonify(attacks)
    except Exception as e:
        logger.exception("Error getting Active Directory attacks:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/oscp/practice_boxes', methods=['GET'])
def oscp_practice_boxes() -> Response:
    """API endpoint to retrieve recommended OSCP practice boxes."""
    try:
        boxes = ethical_hacking_assistant.oscp_resources.get_oscp_practice_boxes()
        return jsonify(boxes)
    except Exception as e:
        logger.exception("Error getting OSCP practice boxes:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

@app.route('/api/oscp/study_plan', methods=['GET'])
def oscp_study_plan() -> Response:
    """API endpoint to generate a structured OSCP study plan."""
    try:
        study_plan = ethical_hacking_assistant.oscp_resources.generate_study_plan()
        return jsonify(study_plan)
    except Exception as e:
        logger.exception("Error generating OSCP study plan:")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

# Main entry point
if __name__ == '__main__':
    """Runs the Flask application with SocketIO support."""
    socketio.run(app, debug=True)