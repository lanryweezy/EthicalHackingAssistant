#!/usr/bin/env python3
"""
Build script for creating installers for all platforms
"""

import os
import sys
import subprocess
import platform
import shutil
import argparse
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a command and return the result"""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    print(f"Success: {result.stdout}")
    return True

def create_assets_directory():
    """Create assets directory with a basic icon"""
    assets_dir = Path("assets")
    assets_dir.mkdir(exist_ok=True)
    
    # Create a simple icon file (placeholder)
    icon_content = """
    # This is a placeholder for the application icon
    # You should replace this with actual icon files:
    # - icon.ico (Windows)
    # - icon.icns (macOS)
    # - icon.png (Linux)
    """
    
    with open(assets_dir / "icon_readme.txt", "w") as f:
        f.write(icon_content)
    
    # Create a simple ICO file placeholder
    ico_file = assets_dir / "icon.ico"
    if not ico_file.exists():
        # Create a minimal ICO file (this is just a placeholder)
        try:
            from PIL import Image
            img = Image.new('RGB', (32, 32), color='red')
            img.save(ico_file, format='ICO')
        except ImportError:
            print("PIL not available, creating text placeholder for icon")
            with open(ico_file, "w") as f:
                f.write("# Icon placeholder")

def install_dependencies():
    """Install build dependencies"""
    dependencies = [
        "pyinstaller",
        "pillow",  # For icon handling
    ]
    
    for dep in dependencies:
        if not run_command(f"pip install {dep}"):
            print(f"Failed to install {dep}")
            return False
    return True

def build_executable():
    """Build the executable using PyInstaller"""
    print("Building executable...")
    
    # Clean previous builds
    if os.path.exists("dist"):
        shutil.rmtree("dist")
    if os.path.exists("build"):
        shutil.rmtree("build")
    
    # Build using the spec file
    if not run_command("pyinstaller app.spec"):
        print("Failed to build executable")
        return False
    
    return True

def build_windows_installer():
    """Build Windows installer using Inno Setup"""
    print("Building Windows installer...")
    
    # Check if Inno Setup is available
    inno_setup_path = r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    if not os.path.exists(inno_setup_path):
        print("Inno Setup not found. Please install Inno Setup 6 from https://www.jrsoftware.org/isdl.php")
        return False
    
    # Create the installer
    if not run_command(f'"{inno_setup_path}" installer_windows.iss'):
        print("Failed to create Windows installer")
        return False
    
    return True

def build_macos_dmg():
    """Build macOS DMG package"""
    print("Building macOS DMG...")
    
    if platform.system() != "Darwin":
        print("DMG creation only supported on macOS")
        return False
    
    # Create DMG structure
    dmg_dir = Path("dist/macos")
    dmg_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy the executable
    app_name = "EthicalHackingAssistant.app"
    app_path = dmg_dir / app_name
    
    # Create .app bundle structure
    app_path.mkdir(exist_ok=True)
    (app_path / "Contents").mkdir(exist_ok=True)
    (app_path / "Contents" / "MacOS").mkdir(exist_ok=True)
    (app_path / "Contents" / "Resources").mkdir(exist_ok=True)
    
    # Copy executable
    shutil.copy("dist/EthicalHackingAssistant", app_path / "Contents" / "MacOS" / "EthicalHackingAssistant")
    
    # Create Info.plist
    info_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Ethical Hacking Assistant</string>
    <key>CFBundleIdentifier</key>
    <string>com.ethicalhacking.assistant</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>EthicalHackingAssistant</string>
    <key>CFBundleIconFile</key>
    <string>icon.icns</string>
</dict>
</plist>"""
    
    with open(app_path / "Contents" / "Info.plist", "w") as f:
        f.write(info_plist)
    
    # Create DMG
    dmg_name = "EthicalHackingAssistant-1.0.dmg"
    if not run_command(f'hdiutil create -srcfolder "{dmg_dir}" -volname "Ethical Hacking Assistant" "dist/{dmg_name}"'):
        print("Failed to create DMG")
        return False
    
    return True

def build_linux_packages():
    """Build Linux packages (.deb and .rpm)"""
    print("Building Linux packages...")
    
    if platform.system() != "Linux":
        print("Linux package creation only supported on Linux")
        return False
    
    # Create .deb package
    if not build_deb_package():
        return False
    
    # Create .rpm package
    if not build_rpm_package():
        return False
    
    return True

def build_deb_package():
    """Build Debian package"""
    print("Building .deb package...")
    
    deb_dir = Path("dist/linux/deb")
    deb_dir.mkdir(parents=True, exist_ok=True)
    
    # Create package structure
    pkg_dir = deb_dir / "ethical-hacking-assistant_1.0_amd64"
    pkg_dir.mkdir(exist_ok=True)
    
    # Create directories
    (pkg_dir / "DEBIAN").mkdir(exist_ok=True)
    (pkg_dir / "usr" / "bin").mkdir(parents=True, exist_ok=True)
    (pkg_dir / "usr" / "share" / "applications").mkdir(parents=True, exist_ok=True)
    (pkg_dir / "usr" / "share" / "pixmaps").mkdir(parents=True, exist_ok=True)
    
    # Copy executable
    shutil.copy("dist/EthicalHackingAssistant", pkg_dir / "usr" / "bin" / "ethical-hacking-assistant")
    
    # Create control file
    control_content = """Package: ethical-hacking-assistant
Version: 1.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Your Name <your.email@example.com>
Description: Ethical Hacking Assistant
 A comprehensive tool for ethical hacking and security research.
"""
    
    with open(pkg_dir / "DEBIAN" / "control", "w") as f:
        f.write(control_content)
    
    # Create desktop entry
    desktop_content = """[Desktop Entry]
Name=Ethical Hacking Assistant
Comment=A comprehensive tool for ethical hacking and security research
Exec=/usr/bin/ethical-hacking-assistant
Icon=ethical-hacking-assistant
Terminal=false
Type=Application
Categories=Development;Security;
"""
    
    with open(pkg_dir / "usr" / "share" / "applications" / "ethical-hacking-assistant.desktop", "w") as f:
        f.write(desktop_content)
    
    # Build package
    if not run_command(f"dpkg-deb --build {pkg_dir}", cwd=str(deb_dir)):
        print("Failed to build .deb package")
        return False
    
    return True

def build_rpm_package():
    """Build RPM package"""
    print("Building .rpm package...")
    
    # Check if rpmbuild is available
    if not run_command("which rpmbuild"):
        print("rpmbuild not found. Please install rpm-build package")
        return False
    
    rpm_dir = Path("dist/linux/rpm")
    rpm_dir.mkdir(parents=True, exist_ok=True)
    
    # Create RPM spec file
    spec_content = """Name: ethical-hacking-assistant
Version: 1.0
Release: 1
Summary: Ethical Hacking Assistant
License: MIT
Group: Development/Tools
BuildArch: x86_64
Requires: python3

%description
A comprehensive tool for ethical hacking and security research.

%prep

%build

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/pixmaps
cp %{_sourcedir}/EthicalHackingAssistant %{buildroot}/usr/bin/ethical-hacking-assistant
cp %{_sourcedir}/ethical-hacking-assistant.desktop %{buildroot}/usr/share/applications/

%files
/usr/bin/ethical-hacking-assistant
/usr/share/applications/ethical-hacking-assistant.desktop

%changelog
* Wed Jan 01 2025 Your Name <your.email@example.com> - 1.0-1
- Initial release
"""
    
    with open(rpm_dir / "ethical-hacking-assistant.spec", "w") as f:
        f.write(spec_content)
    
    # Copy files to SOURCES
    sources_dir = rpm_dir / "SOURCES"
    sources_dir.mkdir(exist_ok=True)
    shutil.copy("dist/EthicalHackingAssistant", sources_dir)
    
    desktop_content = """[Desktop Entry]
Name=Ethical Hacking Assistant
Comment=A comprehensive tool for ethical hacking and security research
Exec=/usr/bin/ethical-hacking-assistant
Icon=ethical-hacking-assistant
Terminal=false
Type=Application
Categories=Development;Security;
"""
    
    with open(sources_dir / "ethical-hacking-assistant.desktop", "w") as f:
        f.write(desktop_content)
    
    # Build RPM
    if not run_command(f"rpmbuild -bb --define '_topdir {rpm_dir.absolute()}' {rpm_dir}/ethical-hacking-assistant.spec"):
        print("Failed to build .rpm package")
        return False
    
    return True

def main():
    """Main build function"""
    parser = argparse.ArgumentParser(description="Build installers for Ethical Hacking Assistant")
    parser.add_argument("--platform", choices=["windows", "macos", "linux", "all"], 
                       default="all", help="Platform to build for")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    
    args = parser.parse_args()
    
    current_platform = platform.system().lower()
    
    print(f"Building for platform: {args.platform}")
    print(f"Current platform: {current_platform}")
    
    # Create assets directory
    create_assets_directory()
    
    # Install dependencies
    if not args.skip_deps:
        if not install_dependencies():
            sys.exit(1)
    
    # Build executable
    if not build_executable():
        sys.exit(1)
    
    # Build platform-specific installers
    if args.platform == "all" or args.platform == "windows":
        if current_platform == "windows":
            build_windows_installer()
        else:
            print("Skipping Windows installer (not on Windows)")
    
    if args.platform == "all" or args.platform == "macos":
        if current_platform == "darwin":
            build_macos_dmg()
        else:
            print("Skipping macOS DMG (not on macOS)")
    
    if args.platform == "all" or args.platform == "linux":
        if current_platform == "linux":
            build_linux_packages()
        else:
            print("Skipping Linux packages (not on Linux)")
    
    print("Build complete!")
    print("Check the 'dist' directory for the generated installers.")

if __name__ == "__main__":
    main()
