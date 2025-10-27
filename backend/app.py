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

# Corrected imports for the new structure
from nmap_helper import NmapHelper
from oscp_resources import OSCPResources
from advanced_features.stream_manager import StreamManager
from src.core.ai_parser import AIParser
from src.core.agent_registry import AgentRegistry
from src.workflows.recon_workflow import ReconWorkflow
from src.agents.recon_agent import ReconAgent
from src.agents.exploit_agent import ExploitAgent
from src.agents.cleanup_agent import CleanupAgent
from src.agents.context_aware_agent import ContextAwareAgent
from src.core.vulnerability_enrichment import VulnerabilityEnrichment
from src.utils.file_utils import allowed_file, secure_filename

app = Flask(__name__,
            static_folder='../frontend/static',
            template_folder='../frontend/templates')

@app.route('/')
def index():
    return render_template('index.html')

app.config['SECRET_KEY'] = 'ethical-hacking-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EthicalHackingAssistant:
    """Main application class for the Ethical Hacking Assistant"""

    def __init__(self, platform_tools, logger):
        """Initialize the main application components"""
        # Initialize core components
        self.ai_parser = AIParser(logger)
        self.agent_registry = AgentRegistry(logger)
        self.platform_tools = platform_tools
        self.logger = logger

        self.nmap_helper = NmapHelper(logger)
        self.oscp_resources = OSCPResources(logger)

        # Register agents
        self.register_agents()



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

platform_tools = PlatformTools(logger)
ethical_hacking_assistant = EthicalHackingAssistant(platform_tools, logger)
stream_manager = StreamManager(socketio)

# Main entry point
if __name__ == '__main__':
    """Runs the Flask application with SocketIO support."""
    socketio.run(app, debug=False, allow_unsafe_werkzeug=True)
