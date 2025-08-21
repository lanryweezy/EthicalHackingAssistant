# Building Installers for Ethical Hacking Assistant

This guide explains how to build standalone installers for Windows, macOS, and Linux.

## Overview

The build system creates:
- **Windows**: `.exe` installer (using Inno Setup)
- **macOS**: `.dmg` package with `.app` bundle
- **Linux**: `.deb` (Debian/Ubuntu) and `.rpm` (Red Hat/Fedora) packages

## Prerequisites

### All Platforms
- Python 3.8 or higher
- pip package manager

### Windows
- [Inno Setup 6](https://www.jrsoftware.org/isdl.php) (for creating `.exe` installer)

### macOS
- Xcode Command Line Tools
- `hdiutil` (included with macOS)

### Linux
- `dpkg-deb` (for `.deb` packages)
- `rpmbuild` (for `.rpm` packages)
  ```bash
  # Ubuntu/Debian
  sudo apt-get install dpkg-dev
  
  # Red Hat/Fedora
  sudo dnf install rpm-build
  ```

## Quick Start

1. **Install dependencies and build for current platform**:
   ```bash
   python build_installers.py
   ```

2. **Build for specific platform**:
   ```bash
   python build_installers.py --platform windows
   python build_installers.py --platform macos
   python build_installers.py --platform linux
   ```

3. **Skip dependency installation** (if already installed):
   ```bash
   python build_installers.py --skip-deps
   ```

## Manual Build Process

### Step 1: Install Build Dependencies
```bash
pip install pyinstaller pillow
```

### Step 2: Build Executable
```bash
pyinstaller app.spec
```

### Step 3: Build Platform-Specific Installers

#### Windows
1. Install [Inno Setup 6](https://www.jrsoftware.org/isdl.php)
2. Run: `"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer_windows.iss`

#### macOS
```bash
# Create .app bundle and DMG
python build_installers.py --platform macos
```

#### Linux
```bash
# Create .deb and .rpm packages
python build_installers.py --platform linux
```

## Output Files

After building, you'll find the installers in the `dist` directory:

```
dist/
├── windows/
│   └── EthicalHackingAssistant-Setup.exe
├── macos/
│   └── EthicalHackingAssistant-1.0.dmg
└── linux/
    ├── deb/
    │   └── ethical-hacking-assistant_1.0_amd64.deb
    └── rpm/
        └── RPMS/
            └── x86_64/
                └── ethical-hacking-assistant-1.0-1.x86_64.rpm
```

## Installation Instructions for End Users

### Windows
1. Download `EthicalHackingAssistant-Setup.exe`
2. Run the installer as Administrator
3. Follow the installation wizard
4. Launch from Start Menu or Desktop shortcut

### macOS
1. Download `EthicalHackingAssistant-1.0.dmg`
2. Open the DMG file
3. Drag the app to the Applications folder
4. Launch from Applications or Launchpad

### Linux (Debian/Ubuntu)
```bash
sudo dpkg -i ethical-hacking-assistant_1.0_amd64.deb
sudo apt-get install -f  # Fix dependencies if needed
```

### Linux (Red Hat/Fedora)
```bash
sudo rpm -ivh ethical-hacking-assistant-1.0-1.x86_64.rpm
```

## Customization

### Application Icon
1. Replace `assets/icon.ico` (Windows)
2. Add `assets/icon.icns` (macOS)
3. Add `assets/icon.png` (Linux)

### Application Metadata
Edit the following files to customize:
- `app.spec` - PyInstaller configuration
- `installer_windows.iss` - Windows installer settings
- `build_installers.py` - Package metadata

### Signing (Optional)

#### Windows
Add code signing certificate to Inno Setup script:
```
SignTool=signtool.exe
SignedUninstaller=yes
```

#### macOS
Add developer certificate:
```bash
codesign --deep --force --verify --verbose --sign "Developer ID Application: Your Name" EthicalHackingAssistant.app
```

## Troubleshooting

### Common Issues

1. **Missing dependencies**: Run `pip install -r requirements.txt`
2. **PyInstaller errors**: Try `pip install --upgrade pyinstaller`
3. **Permission errors**: Run as Administrator/sudo
4. **Missing tools**: Install platform-specific build tools

### Windows Issues
- **Inno Setup not found**: Install from [official website](https://www.jrsoftware.org/isdl.php)
- **Antivirus blocking**: Add exception for build directory

### macOS Issues
- **Permission denied**: Run `chmod +x` on the executable
- **App not verified**: Right-click → Open → Open anyway

### Linux Issues
- **dpkg-deb not found**: Install with `sudo apt-get install dpkg-dev`
- **rpm-build not found**: Install with `sudo dnf install rpm-build`

## Development Notes

### File Structure
```
EthicalHackingAssistant/
├── gui_main.py              # Main GUI application
├── app.spec                 # PyInstaller specification
├── installer_windows.iss    # Windows installer script
├── build_installers.py      # Cross-platform build script
├── assets/                  # Icons and resources
├── src/                     # Source code
├── config/                  # Configuration files
└── dist/                    # Built installers (created)
```

### Adding New Platforms
1. Add platform detection to `build_installers.py`
2. Create platform-specific build function
3. Add packaging commands for the new platform

### Testing
Test the built installers on clean systems:
- Windows: Windows 10/11
- macOS: macOS 10.15+
- Linux: Ubuntu 20.04+, Fedora 35+

## Distribution

### Hosting Options
- **GitHub Releases**: Attach installers to releases
- **Website**: Host on your own server
- **Package Repositories**: Submit to official repos

### Update Mechanism
Consider implementing auto-update functionality:
- Windows: Use Squirrel.Windows
- macOS: Use Sparkle framework
- Linux: Use system package managers

## Security Considerations

1. **Code signing**: Sign all executables
2. **Checksums**: Provide SHA256 checksums
3. **Virus scanning**: Scan before distribution
4. **Secure hosting**: Use HTTPS for downloads

## License

Make sure to include appropriate license files:
- `LICENSE` - Main license
- `THIRD_PARTY_LICENSES` - Dependencies licenses
