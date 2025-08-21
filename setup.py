#!/usr/bin/env python3
"""
Setup script for the Ethical Hacking Assistant
Packages the application for Windows distribution
"""

import os
import sys
from pathlib import Path

def create_spec_file():
    """Create PyInstaller spec file for Windows"""
    
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Define the main script
main_script = 'main.py'

# Define additional data files
added_files = [
    ('translations', 'translations'),
    ('config', 'config'),
    ('docs', 'docs'),
    ('README.md', '.'),
    ('requirements.txt', '.'),
]

# Define hidden imports (modules that PyInstaller might miss)
hidden_imports = [
    'prompt_toolkit',
    'prompt_toolkit.application',
    'prompt_toolkit.key_binding',
    'prompt_toolkit.layout',
    'prompt_toolkit.widgets',
    'prompt_toolkit.shortcuts',
    'prompt_toolkit.formatted_text',
    'prompt_toolkit.styles',
    'prompt_toolkit.completion',
    'prompt_toolkit.history',
    'prompt_toolkit.auto_suggest',
    'prompt_toolkit.validation',
    'psutil',
    'uuid',
    'json',
    'logging',
    'threading',
    'subprocess',
    'time',
    'datetime',
    'os',
    'sys',
    'shlex',
    'importlib',
    'pathlib',
    'collections',
    'typing',
    'dataclasses',
    'enum',
    'weakref',
    'queue',
    'concurrent.futures',
    'asyncio',
    're',
]

a = Analysis(
    [main_script],
    pathex=[],
    binaries=[],
    datas=added_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='EthicalHackingAssistant',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if os.path.exists('assets/icon.ico') else None,
)
'''
    
    with open('EthicalHackingAssistant.spec', 'w') as f:
        f.write(spec_content)
    
    print("✅ Created EthicalHackingAssistant.spec")

def install_packaging_dependencies():
    """Install required dependencies for packaging"""
    import subprocess
    
    print("📦 Installing packaging dependencies...")
    
    dependencies = [
        'pyinstaller>=5.0.0',
        'auto-py-to-exe>=2.0.0',  # Optional GUI for PyInstaller
    ]
    
    for dep in dependencies:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', dep])
            print(f"✅ Installed {dep}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {dep}: {e}")
            return False
    
    return True

def create_config_files():
    """Create default configuration files if they don't exist"""
    
    # Create config directory
    config_dir = Path('config')
    config_dir.mkdir(exist_ok=True)
    
    # Create default config
    default_config = '''[app]
name = "Ethical Hacking Assistant"
version = "1.0.0"
debug = false

[ui]
theme = "dark"
language = "en"
show_welcome = true
auto_save = true

[security]
enable_command_validation = true
max_risk_level = 3
log_all_commands = true

[agents]
enabled = [
    "recon",
    "vulnerability_scanner",
    "exploit",
    "information_gathering",
    "network_traffic_analysis",
    "web_application_analysis",
    "password_cracking",
    "privilege_escalation",
    "persistence",
    "cleanup",
    "documentation"
]

[logging]
level = "INFO"
file = "app.log"
max_size = "10MB"
backup_count = 3
'''
    
    config_file = config_dir / 'default.toml'
    if not config_file.exists():
        with open(config_file, 'w') as f:
            f.write(default_config)
        print("✅ Created default.toml")
    
    # Create UI config
    ui_config = '''# UI Configuration for Enhanced Terminal
modes:
  - name: "agent"
    description: "AI interprets commands and selects appropriate tools"
    color: "blue"
  - name: "terminal"
    description: "Direct command execution with safety checks"
    color: "green"
  - name: "interactive"
    description: "AI suggests commands for user approval"
    color: "yellow"
  - name: "automated"
    description: "Automated workflow execution"
    color: "red"

themes:
  dark:
    background: "#1e1e1e"
    foreground: "#ffffff"
    primary: "#007acc"
    secondary: "#6c6c6c"
    success: "#4caf50"
    warning: "#ff9800"
    error: "#f44336"
    security: "#e91e63"

shortcuts:
  help: "F1"
  tools: "F2"
  logs: "F3"
  mode: "F4"
  refresh: "F5"
  exit: "Ctrl+C"
'''
    
    ui_config_file = config_dir / 'ui_config.yaml'
    if not ui_config_file.exists():
        with open(ui_config_file, 'w') as f:
            f.write(ui_config)
        print("✅ Created ui_config.yaml")

def create_assets():
    """Create assets directory and icon"""
    assets_dir = Path('assets')
    assets_dir.mkdir(exist_ok=True)
    
    # Create a simple text-based icon file (you can replace with actual .ico file)
    icon_content = '''This is a placeholder for the application icon.
Replace this file with a proper .ico file for the Windows executable.
Recommended size: 256x256 pixels
'''
    
    icon_file = assets_dir / 'icon.txt'
    with open(icon_file, 'w') as f:
        f.write(icon_content)
    
    print("✅ Created assets directory (add icon.ico for proper icon)")

def build_executable():
    """Build the Windows executable"""
    
    print("🔨 Building Windows executable...")
    
    try:
        # Import PyInstaller here to avoid import errors
        import PyInstaller.__main__
        
        # Run PyInstaller with the spec file
        PyInstaller.__main__.run([
            'EthicalHackingAssistant.spec',
            '--clean',
            '--noconfirm'
        ])
        
        print("✅ Build completed successfully!")
        print("📁 Executable location: dist/EthicalHackingAssistant.exe")
        
        # Check if executable was created
        exe_path = Path('dist/EthicalHackingAssistant.exe')
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"📊 Executable size: {size_mb:.2f} MB")
            return True
        else:
            print("❌ Executable not found after build")
            return False
            
    except Exception as e:
        print(f"❌ Build failed: {e}")
        return False

def create_installer_script():
    """Create NSIS installer script for Windows"""
    
    installer_script = '''# NSIS Installer Script for Ethical Hacking Assistant
# This script can be used with NSIS (Nullsoft Scriptable Install System)
# to create a Windows installer

!define APPNAME "Ethical Hacking Assistant"
!define COMPANYNAME "Ethical Hacking Team"
!define DESCRIPTION "Advanced Penetration Testing Terminal"
!define VERSIONMAJOR 1
!define VERSIONMINOR 0
!define VERSIONBUILD 0
!define HELPURL "https://github.com/yourusername/EthicalHackingAssistant"
!define UPDATEURL "https://github.com/yourusername/EthicalHackingAssistant"
!define ABOUTURL "https://github.com/yourusername/EthicalHackingAssistant"
!define INSTALLSIZE 50000  # Size in KB

RequestExecutionLevel admin

InstallDir "$PROGRAMFILES64\\${APPNAME}"

LicenseData "LICENSE"
Name "${APPNAME}"
Icon "assets\\icon.ico"
outFile "EthicalHackingAssistant_Installer.exe"

page license
page directory
page instfiles

!macro VerifyUserIsAdmin
UserInfo::GetAccountType
pop $0
${If} $0 != "admin"
    messageBox mb_iconstop "Administrator rights required!"
    setErrorLevel 740
    quit
${EndIf}
!macroend

function .onInit
    !insertmacro VerifyUserIsAdmin
functionEnd

section "install"
    setOutPath $INSTDIR
    file /r "dist\\*"
    
    writeUninstaller "$INSTDIR\\uninstall.exe"
    
    createDirectory "$SMPROGRAMS\\${APPNAME}"
    createShortCut "$SMPROGRAMS\\${APPNAME}\\${APPNAME}.lnk" "$INSTDIR\\EthicalHackingAssistant.exe"
    createShortCut "$DESKTOP\\${APPNAME}.lnk" "$INSTDIR\\EthicalHackingAssistant.exe"
    
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "DisplayName" "${APPNAME}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "UninstallString" "$INSTDIR\\uninstall.exe"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "QuietUninstallString" "$INSTDIR\\uninstall.exe /S"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "DisplayIcon" "$INSTDIR\\EthicalHackingAssistant.exe"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "Publisher" "${COMPANYNAME}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "HelpLink" "${HELPURL}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "URLUpdateInfo" "${UPDATEURL}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "URLInfoAbout" "${ABOUTURL}"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "DisplayVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}"
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "VersionMajor" ${VERSIONMAJOR}
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "VersionMinor" ${VERSIONMINOR}
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "NoRepair" 1
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}" "EstimatedSize" ${INSTALLSIZE}
sectionEnd

section "uninstall"
    delete "$INSTDIR\\EthicalHackingAssistant.exe"
    delete "$INSTDIR\\uninstall.exe"
    
    rmDir /r "$INSTDIR"
    
    delete "$SMPROGRAMS\\${APPNAME}\\${APPNAME}.lnk"
    rmDir "$SMPROGRAMS\\${APPNAME}"
    
    delete "$DESKTOP\\${APPNAME}.lnk"
    
    DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${APPNAME}"
sectionEnd
'''
    
    with open('installer.nsi', 'w') as f:
        f.write(installer_script)
    
    print("✅ Created installer.nsi (requires NSIS to build installer)")

def create_batch_scripts():
    """Create batch scripts for easy building and running"""
    
    # Build script
    build_script = '''@echo off
echo Building Ethical Hacking Assistant for Windows...
echo.

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
pip install pyinstaller>=5.0.0

REM Create build
echo Creating executable...
python setup.py build

echo.
echo Build completed!
echo Executable location: dist\\EthicalHackingAssistant.exe
echo.
pause
'''
    
    with open('build.bat', 'w') as f:
        f.write(build_script)
    
    # Run script
    run_script = '''@echo off
echo Starting Ethical Hacking Assistant...
echo.

REM Check if executable exists
if exist "dist\\EthicalHackingAssistant.exe" (
    echo Running from dist directory...
    cd dist
    EthicalHackingAssistant.exe
) else (
    echo Executable not found. Running from source...
    python main.py
)

echo.
pause
'''
    
    with open('run.bat', 'w') as f:
        f.write(run_script)
    
    print("✅ Created build.bat and run.bat")

def main():
    """Main setup function"""
    
    print("🚀 Setting up Ethical Hacking Assistant for Windows packaging...")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Install packaging dependencies
    if not install_packaging_dependencies():
        print("❌ Failed to install packaging dependencies")
        return False
    
    # Create necessary files
    create_config_files()
    create_assets()
    create_spec_file()
    create_installer_script()
    create_batch_scripts()
    
    # Build executable
    print("\n🔨 Building executable...")
    if build_executable():
        print("\n✅ Packaging completed successfully!")
        print("\n📋 Next steps:")
        print("1. Test the executable: dist/EthicalHackingAssistant.exe")
        print("2. Run: .\\run.bat")
        print("3. Create installer: Use installer.nsi with NSIS")
        print("4. Add proper icon: Replace assets/icon.txt with icon.ico")
        
        return True
    else:
        print("\n❌ Packaging failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
