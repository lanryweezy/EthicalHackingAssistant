#!/usr/bin/env python3
"""
Simple build script for Windows packaging
"""

import os
import sys
import subprocess
from pathlib import Path

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    
    try:
        # Install main dependencies
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Main dependencies installed")
        
        # Install PyInstaller
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller>=5.0.0"])
        print("✅ PyInstaller installed")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    dirs = ["config", "assets", "dist", "build"]
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"✅ Created {dir_name}/ directory")

def build_with_pyinstaller():
    """Build using PyInstaller directly"""
    print("🔨 Building with PyInstaller...")
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--console",
        "--name", "EthicalHackingAssistant",
        "--add-data", "translations;translations",
        "--add-data", "config;config",
        "--add-data", "README.md;.",
        "--hidden-import", "prompt_toolkit",
        "--hidden-import", "prompt_toolkit.application",
        "--hidden-import", "prompt_toolkit.key_binding",
        "--hidden-import", "prompt_toolkit.layout",
        "--hidden-import", "prompt_toolkit.widgets",
        "--hidden-import", "prompt_toolkit.shortcuts",
        "--hidden-import", "prompt_toolkit.formatted_text",
        "--hidden-import", "prompt_toolkit.styles",
        "--hidden-import", "prompt_toolkit.completion",
        "--hidden-import", "prompt_toolkit.history",
        "--hidden-import", "prompt_toolkit.auto_suggest",
        "--hidden-import", "prompt_toolkit.validation",
        "--hidden-import", "psutil",
        "--hidden-import", "uuid",
        "--hidden-import", "json",
        "--hidden-import", "logging",
        "--hidden-import", "threading",
        "--hidden-import", "subprocess",
        "--hidden-import", "concurrent.futures",
        "--hidden-import", "asyncio",
        "--hidden-import", "queue",
        "--hidden-import", "weakref",
        "--hidden-import", "dataclasses",
        "--hidden-import", "enum",
        "--clean",
        "main.py"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Build completed successfully!")
            exe_path = Path("dist/EthicalHackingAssistant.exe")
            if exe_path.exists():
                size_mb = exe_path.stat().st_size / (1024 * 1024)
                print(f"📊 Executable size: {size_mb:.2f} MB")
                print(f"📁 Executable location: {exe_path}")
                return True
            else:
                print("❌ Executable not found after build")
                return False
        else:
            print(f"❌ Build failed with return code {result.returncode}")
            print(f"Error output: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Build failed: {e}")
        return False

def create_test_config():
    """Create test configuration files"""
    
    # Create config directory
    config_dir = Path("config")
    config_dir.mkdir(exist_ok=True)
    
    # Create minimal config for testing
    config_content = '''[app]
name = "Ethical Hacking Assistant"
version = "1.0.0"
debug = false

[ui]
theme = "dark"
language = "en"

[security]
enable_command_validation = true
max_risk_level = 3

[logging]
level = "INFO"
file = "app.log"
'''
    
    config_file = config_dir / "default.toml"
    with open(config_file, 'w') as f:
        f.write(config_content)
    
    print("✅ Created test configuration")

def main():
    """Main build function"""
    print("🚀 Building Ethical Hacking Assistant for Windows")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Create directories
    create_directories()
    
    # Create test config
    create_test_config()
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Build executable
    if build_with_pyinstaller():
        print("\n🎉 Build completed successfully!")
        print("\n📋 Next steps:")
        print("1. Test the executable: dist/EthicalHackingAssistant.exe")
        print("2. Check if it runs without errors")
        print("3. Test different features and modes")
        
        return True
    else:
        print("\n❌ Build failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
