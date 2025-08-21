# Ethical Hacking Assistant - Modern Terminal

A futuristic, Warp.dev-inspired terminal application designed specifically for ethical hackers and penetration testers. Features a beautiful Matrix/Cyberpunk aesthetic with powerful AI-assisted hacking capabilities.

![Version](https://img.shields.io/badge/version-2.0.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20|%20macOS%20|%20Linux-lightgrey.svg)

## 🚀 Features

### Futuristic Design
- **Matrix Green Theme** (default) with glowing effects and animations
- **Cyberpunk Theme** with neon colors and holographic effects
- **Dracula** and **Nord** themes for preference
- Animated grid background with scanlines
- Glitch effects on ASCII art
- Smooth transitions and hover effects

### AI-Powered Modes
- **🤖 Agent Mode**: AI interprets natural language and suggests commands
- **💻 Terminal Mode**: Direct command execution with safety filters
- **🔍 Scan Mode**: Automated reconnaissance with live progress
- **🚀 Exploit Mode**: Vulnerability assessment and exploit suggestions

### Real-Time Features
- Live system stats (CPU, Memory, Commands)
- WebSocket-based real-time updates
- Animated scan progress with phase tracking
- Service discovery visualization
- Side panel for detailed results

### Modern Terminal Features
- Command history with arrow key navigation
- Tab autocomplete for commands
- Multi-theme support with live switching
- Responsive design for all screen sizes
- Custom notifications system
- Settings modal for customization

## 🎨 Screenshots

### Matrix Theme (Default)
- Green phosphor glow effects
- Classic hacker aesthetic
- Animated ASCII art with glitch effects

### Cyberpunk Theme
- Neon pink and blue colors
- Futuristic holographic effects
- High contrast for better visibility

## 🔧 Installation

### Quick Start (Development)

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ethical-hacking-assistant.git
   cd ethical-hacking-assistant/modern_gui
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Node.js dependencies** (for Electron)
   ```bash
   npm install
   ```

4. **Run the application**
   ```bash
   # Option 1: Run as web app
   python app.py
   # Open http://localhost:5000 in your browser

   # Option 2: Run as desktop app
   npm start
   ```

### Building Installers

#### Windows (.exe)
```bash
npm run build-win
# Output: dist/Ethical Hacking Assistant Setup 2.0.0.exe
```

#### macOS (.dmg)
```bash
npm run build-mac
# Output: dist/Ethical Hacking Assistant-2.0.0.dmg
```

#### Linux (.deb, .rpm, .AppImage)
```bash
npm run build-linux
# Output: dist/ethical-hacking-assistant_2.0.0_amd64.deb
#         dist/ethical-hacking-assistant-2.0.0.x86_64.rpm
#         dist/Ethical Hacking Assistant-2.0.0.AppImage
```

## 📱 Usage

### Basic Commands

```bash
# Help
/help              # Show available commands

# Scanning
/scan 192.168.1.1  # Scan a target
scan the network   # Natural language in agent mode

# Exploits
/exploit target    # Search for exploits
find vulnerabilities in apache  # Natural language

# Utilities
/clear            # Clear terminal
/theme cyberpunk  # Change theme
/report           # Generate report
```

### Mode Examples

#### Agent Mode (AI-Powered)
```
[agent] > scan the web server at example.com
AI: Analyzing request...
Suggested commands:
▶ nmap -sS -sV example.com
▶ nikto -h example.com
▶ dirb http://example.com
```

#### Scan Mode (Automated)
```
[scan] > 192.168.1.100
Scanning: 192.168.1.100
✓ Port Discovery      [completed]
✓ Service Detection   [completed]
→ Vulnerability Assessment [running]
○ Report Generation   [pending]

Discovered Services:
22   SSH     OpenSSH 8.2
80   HTTP    Apache 2.4.41
443  HTTPS   Apache 2.4.41
```

## 🏗️ Architecture

```
modern_gui/
├── app.py                 # Flask backend with SocketIO
├── requirements.txt       # Python dependencies
├── package.json          # Node.js configuration
├── electron/
│   └── main.js          # Electron main process
├── templates/
│   └── index.html       # Main HTML template
├── static/
│   ├── css/
│   │   ├── terminal.css # Main styles
│   │   └── animations.css # Animations
│   └── js/
│       └── terminal.js  # Terminal functionality
└── assets/              # Icons and images
```

## 🛠️ Technologies

- **Backend**: Python, Flask, Flask-SocketIO
- **Frontend**: HTML5, CSS3, JavaScript ES6+
- **Desktop**: Electron
- **Styling**: Custom CSS with CSS Variables
- **Real-time**: WebSockets (Socket.IO)
- **Fonts**: JetBrains Mono

## 🎯 What Makes It Like Warp.dev

1. **Modern UI/UX**: Beautiful, responsive interface with smooth animations
2. **AI Integration**: Natural language command interpretation
3. **Real-time Features**: Live updates and progress tracking
4. **Developer Focus**: Built specifically for the target audience
5. **Cross-platform**: Native desktop app for all major OS
6. **Themes**: Multiple beautiful themes to choose from
7. **Performance**: Fast, responsive, and efficient

## 🔒 Security & Ethics

- **Ethical Use Only**: Built for authorized security testing
- **Safety Filters**: Dangerous commands are blocked
- **Audit Trail**: All commands are logged
- **Legal Compliance**: Includes warnings and disclaimers

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for ETHICAL HACKING and SECURITY RESEARCH only. Users are responsible for complying with all applicable laws and regulations. Use only on systems you own or have explicit permission to test.

## 🙏 Acknowledgments

- Inspired by Warp.dev's beautiful terminal design
- Matrix movie aesthetics for the default theme
- The ethical hacking community for feedback and suggestions

---

**Remember**: With great power comes great responsibility. Always hack ethically! 🛡️
