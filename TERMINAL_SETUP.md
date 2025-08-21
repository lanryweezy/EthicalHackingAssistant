# Ethical Hacking Assistant Terminal Setup

This guide will help you set up the Ethical Hacking Assistant to run in its own dedicated terminal window with proper styling and functionality.

## Fixed Issues

✅ **XML Parsing Error Fixed**: The `not well-formed (invalid token): line 1, column 30` error has been resolved by fixing malformed HTML tags in the CLI prompt formatting.

## Quick Start

### Option 1: Using the Batch Script (Simplest)
1. Double-click `run_terminal.bat`
2. The application will install dependencies and start automatically

### Option 2: Using PowerShell Script (Recommended)
1. Run: `powershell -ExecutionPolicy Bypass -File run_terminal.ps1`
2. To install dependencies: `powershell -ExecutionPolicy Bypass -File run_terminal.ps1 -InstallDeps`

### Option 3: Manual Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Run the application: `python main.py`

## Windows Terminal Integration

For the best experience, add the Ethical Hacking Assistant as a custom profile in Windows Terminal:

1. Open Windows Terminal
2. Press `Ctrl+,` to open settings
3. Click "Add a new profile" → "New empty profile"
4. Copy the contents of `terminal_profile.json` into the profile configuration
5. Update the `commandline` and `startingDirectory` paths to match your installation directory

### Example Profile Configuration:
```json
{
  "name": "Ethical Hacking Assistant",
  "commandline": "powershell.exe -ExecutionPolicy Bypass -File \"C:\\Path\\To\\Your\\Project\\run_terminal.ps1\"",
  "startingDirectory": "C:\\Path\\To\\Your\\Project",
  "icon": "🛡️",
  "colorScheme": "Campbell",
  "background": "#0C0C0C",
  "foreground": "#CCCCCC"
}
```

## Features

- **Dedicated Terminal Window**: Runs in its own terminal with custom styling
- **Automatic Dependency Installation**: Dependencies are installed automatically
- **Color-Coded Interface**: Different colors for different message types
- **Command History**: Maintains command history across sessions
- **Multiple Modes**: Agent, Terminal, More, and Auto modes
- **Ethical Guidelines**: Built-in ethical hacking guidelines and warnings
- **Safe Command Filtering**: Prevents execution of dangerous commands
- **Session Logging**: All actions are logged for accountability

## Available Modes

1. **Agent Mode**: AI interprets your commands and runs appropriate tools
2. **Terminal Mode**: Direct execution of shell commands with safety checks
3. **More Mode**: AI suggests commands for your approval
4. **Auto Mode**: Run predefined workflows automatically

## Basic Commands

- `/help` - Show help information
- `/mode [mode]` - Switch between modes (agent, terminal, more, auto)
- `/clear` - Clear the screen
- `/ethical` - Display ethical guidelines
- `/info` - Show system information
- `/status` - Show current session status
- `/history` - Show command history
- `/exit` - Exit the application

## Example Usage

```
[agent] > scan the target 192.168.1.1
[terminal] > nmap -sV 192.168.1.1
[more] > suggest ways to enumerate open ports
[auto] > recon 192.168.1.1
```

## Troubleshooting

### Common Issues:

1. **Python not found**: Make sure Python is installed and added to your PATH
2. **Permission errors**: Run PowerShell as Administrator if needed
3. **Module not found**: Install dependencies using: `pip install -r requirements.txt`
4. **XML parsing errors**: These have been fixed in the latest version

### If the application doesn't start:

1. Check Python installation: `python --version`
2. Install dependencies manually: `pip install -r requirements.txt`
3. Run directly: `python main.py`
4. Check the log files in the `logs/` directory for error details

## Security Notes

- This tool is for ETHICAL HACKING and SECURITY RESEARCH only
- Only use on systems you own or have explicit permission to test
- All commands are logged for accountability
- Dangerous commands are filtered and blocked
- Follow the ethical guidelines displayed in the application

## Customization

You can customize the terminal appearance by:
1. Modifying the PowerShell script colors
2. Updating the Windows Terminal profile configuration
3. Editing the `config/ui_config.yaml` file for CLI behavior
4. Adjusting the color scheme in the application settings

## Support

If you encounter any issues:
1. Check the log files in the `logs/` directory
2. Ensure all dependencies are installed
3. Verify Python version compatibility
4. Run the application directly with `python main.py` to see error messages
