# Ethical Hacking Assistant User Guide

## Introduction
The Ethical Hacking Assistant is a terminal-based application designed to assist security professionals in conducting penetration tests and security assessments. It provides a modular, agent-based system that automates various aspects of ethical hacking.

This guide will help you get started with using the Ethical Hacking Assistant effectively.

## Installation

### Prerequisites
- Python 3.8 or higher
- Git (for cloning the repository)
- Required security tools (specific to the agents you'll use)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/EthicalHackingAssistant.git
   cd EthicalHackingAssistant
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure the application:
   - Edit `config/default.toml` to set up your preferences
   - Ensure all required tools are installed on your system

## Quick Start

### Starting the Application
Run the application using:
```bash
python src/main.py
```

### Basic Usage
The terminal interface has a command-line style interaction. Here are some basic commands:

- `help` - Show available commands
- `list agents` - List all available agents
- `use <agent>` - Select an agent to use
- `set <option> <value>` - Set an option for the current task
- `run` - Execute the current task
- `exit` - Exit the application

### Example Session

```
$ python src/main.py

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║             ETHICAL HACKING ASSISTANT TERMINAL                ║
║                                                               ║
║              An agent-based penetration testing               ║
║                   and security analysis tool                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Type 'help' to see available commands.
Type 'exit' to quit the application.

[EHA]> list agents
Available agents:
1. vulnerability_scanner
2. information_gathering
3. exploit_execution
...

[EHA]> use information_gathering
Selected agent: Information Gathering

[EHA/info_gathering]> list tasks
Available tasks:
1. dns - Gather DNS information
2. whois - Gather WHOIS information
3. port_scan - Scan ports
4. osint - Gather OSINT information

[EHA/info_gathering]> set task dns
Task set to: dns

[EHA/info_gathering]> set target example.com
Target set to: example.com

[EHA/info_gathering]> set tool dig
Tool set to: dig

[EHA/info_gathering]> run
Running DNS information gathering on example.com...
Information gathering complete.
Results saved to data/info_gathering/dns_example_com_20250715_123456.json

[EHA/info_gathering]> exit
Exiting...
```

## Working with Sessions

Sessions in the Ethical Hacking Assistant allow you to organize your penetration testing activities:

### Starting a Session

```
[EHA]> use coordination
Selected agent: Agent Coordination Manager

[EHA/coordination]> set type start_session
Task type set to: start_session

[EHA/coordination]> set name "Example Company Pentest"
Session name set to: Example Company Pentest

[EHA/coordination]> set target example.com
Target set to: example.com

[EHA/coordination]> run
Starting new session: Example Company Pentest (Target: example.com)
Session started with ID: Example_Company_Pentest_20250715_123456
```

### Running Workflows

Workflows combine multiple tasks across different agents:

```
[EHA/coordination]> set type execute_workflow
Task type set to: execute_workflow

[EHA/coordination]> set workflow_id basic_pentest
Workflow ID set to: basic_pentest

[EHA/coordination]> set session_id Example_Company_Pentest_20250715_123456
Session ID set to: Example_Company_Pentest_20250715_123456

[EHA/coordination]> set params.target example.com
Parameter target set to: example.com

[EHA/coordination]> run
Executing workflow: Basic Pentest
Workflow started with 3 tasks
```

### Ending a Session

```
[EHA/coordination]> set type end_session
Task type set to: end_session

[EHA/coordination]> set session_id Example_Company_Pentest_20250715_123456
Session ID set to: Example_Company_Pentest_20250715_123456

[EHA/coordination]> run
Session ended: Example Company Pentest (Duration: 45.3 minutes)
```

## Generating Reports

The Documentation Agent can generate reports for your penetration testing sessions:

```
[EHA]> use documentation
Selected agent: Documentation Agent

[EHA/documentation]> set type generate_report
Task type set to: generate_report

[EHA/documentation]> set session_id Example_Company_Pentest_20250715_123456
Session ID set to: Example_Company_Pentest_20250715_123456

[EHA/documentation]> set template technical_report
Template set to: technical_report

[EHA/documentation]> run
Generating report for session Example_Company_Pentest_20250715_123456 using template technical_report
Report generated: docs/reports/report_Example_Company_Pentest_20250715_123456_technical_report_20250715_123456.txt
```

## Advanced Usage

### Custom Workflows
You can create custom workflows to automate complex testing scenarios. See the [Agents Documentation](agents/README.md) for details on creating workflows.

### Adding New Tools
The Tool Manager can help you install and manage security tools:

```
[EHA]> use tool_manager
Selected agent: Tool Manager

[EHA/tool_manager]> set action install
Action set to: install

[EHA/tool_manager]> set tool_name sqlmap
Tool name set to: sqlmap

[EHA/tool_manager]> run
Installing sqlmap...
Tool sqlmap successfully installed
```

### Customizing the UI
You can customize the terminal UI by editing the UI settings in `config/default.toml`:

```toml
[ui]
color_scheme = {
    "normal" = {"fg" = "green", "bg" = null, "style" = null},
    "error" = {"fg" = "red", "bg" = null, "style" = "bold"},
    # ...
}
background = "dark"
clear_on_start = true
```

## Troubleshooting

### Common Issues

#### Tool Not Found
If you see an error like "Tool not available on system", make sure:
- The tool is installed on your system
- The tool is in your PATH
- You have the necessary permissions to run the tool

#### Permission Denied
Some tools require elevated privileges:
- Use sudo when necessary (configure in the settings)
- Ensure you have the necessary permissions

#### Configuration Problems
If you experience configuration-related issues:
- Check your `config/default.toml` file
- Ensure all paths are correct
- Make sure referenced files exist

### Getting Help
If you need further assistance:
- Check the documentation in the `docs` directory
- Look for examples in the `examples` directory
- Submit an issue on the project's GitHub repository

## Security Considerations

### Ethical Use
The Ethical Hacking Assistant is designed for ethical hacking and security testing. Always:
- Obtain proper authorization before testing any system
- Follow responsible disclosure practices
- Adhere to applicable laws and regulations

### Tool Limitations
Remember that security tools can have false positives and false negatives. Always:
- Verify findings manually
- Use multiple tools to confirm vulnerabilities
- Apply human judgment to interpret results

## Legal Disclaimer
The Ethical Hacking Assistant is provided for legitimate security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any system and must comply with all applicable laws and regulations.

## License
[Insert your license information here]
