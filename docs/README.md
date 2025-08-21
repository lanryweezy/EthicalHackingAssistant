# Ethical Hacking Assistant

## Overview
The Ethical Hacking Assistant is a modular, agent-based tool designed for penetration testing. It features several agents focusing on various aspects of security testing, including vulnerability scanning, malware analysis, and more.

## Setup
1. **Install Dependencies:**
   Ensure Python and the required tools (e.g., Nmap, Metasploit) are installed on your system.

2. **Configuration:**
   Configure the assistant using `config/default.toml`, defining tools and paths.

3. **Run the Application:**
   Execute the main script to start the terminal-based user interface.
   ```bash
   python src/main.py
   ```

## Agents
- **Vulnerability Scanner:** Scans for security vulnerabilities.
- **Information Gathering:** Collects information about target systems.
- **Exploit Execution:** Executes exploits against vulnerabilities.
- **...**

Refer to the documentation for each agent in the `/docs/agents` folder.

## Contributing
Please read `CONTRIBUTING.md` for details on the code of conduct and the process for submitting pull requests.
