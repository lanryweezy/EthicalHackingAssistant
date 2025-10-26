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

# Main entry point
if __name__ == '__main__':
    """Runs the Flask application with SocketIO support."""
    socketio.run(app, debug=False, allow_unsafe_werkzeug=True)
