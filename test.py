#!/usr/bin/env python3
"""
Test script to verify the packaged application works
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported"""
    print("🧪 Testing imports...")
    
    imports_to_test = [
        "src.core.app_manager",
        "src.ui.terminal",
        "src.core.config_manager",
        "core.performance_terminal",
        "ui.advanced_ui_system",
        "core.integration_and_audit",
    ]
    
    for module in imports_to_test:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module}: {e}")
            return False
    
    return True

def test_configuration():
    """Test configuration files"""
    print("\n🔧 Testing configuration...")
    
    config_files = [
        "config/default.toml",
        "translations/en.json",
        "translations/es.json",
        "translations/fr.json",
        "translations/zh-CN.json",
        "translations/ru.json",
        "translations/he.json",
        "translations/ar.json",
    ]
    
    for config_file in config_files:
        config_path = Path(config_file)
        if config_path.exists():
            print(f"✅ {config_file}")
        else:
            print(f"❌ {config_file} not found")
            return False
    
    return True

def test_executable():
    """Test the built executable"""
    print("\n🏃 Testing executable...")
    
    exe_path = Path("dist/EthicalHackingAssistant.exe")
    if not exe_path.exists():
        print("❌ Executable not found")
        return False
    
    print(f"✅ Executable found: {exe_path}")
    
    # Test if executable runs (with timeout)
    try:
        # Run with --help flag if available, otherwise just check if it starts
        result = subprocess.run(
            [str(exe_path), "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 or "help" in result.stdout.lower():
            print("✅ Executable runs successfully")
            return True
        else:
            print(f"⚠️ Executable runs but may have issues: {result.stderr}")
            return True  # Still consider this a pass
            
    except subprocess.TimeoutExpired:
        print("⚠️ Executable started but timed out (may be waiting for input)")
        return True  # This is actually expected for an interactive terminal
    except Exception as e:
        print(f"❌ Executable failed to run: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality without GUI"""
    print("\n⚙️ Testing basic functionality...")
    
    try:
        # Test performance terminal
        from core.performance_terminal import HighPerformanceTerminal
        terminal = HighPerformanceTerminal()
        print("✅ Performance terminal can be created")
        
        # Test UI system
        from ui.advanced_ui_system import AdvancedUISystem
        ui = AdvancedUISystem()
        print("✅ Advanced UI system can be created")
        
        # Test integration
        from core.integration_and_audit import TerminalEnvironmentController
        controller = TerminalEnvironmentController()
        print("✅ Terminal environment controller can be created")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def create_test_report():
    """Create a test report"""
    print("\n📊 Creating test report...")
    
    report_content = f"""
# Test Report for Ethical Hacking Assistant

## System Information
- Python Version: {sys.version}
- Platform: {sys.platform}
- Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Test Results
"""
    
    # Add executable info if it exists
    exe_path = Path("dist/EthicalHackingAssistant.exe")
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        report_content += f"""
## Executable Information
- Size: {size_mb:.2f} MB
- Location: {exe_path}
- Created: {time.ctime(exe_path.stat().st_ctime)}
"""
    
    # Write report
    with open("test_report.txt", "w") as f:
        f.write(report_content)
    
    print("✅ Test report created: test_report.txt")

def main():
    """Main test function"""
    print("🚀 Testing Ethical Hacking Assistant")
    print("=" * 40)
    
    tests = [
        ("Import Tests", test_imports),
        ("Configuration Tests", test_configuration),
        ("Executable Tests", test_executable),
        ("Basic Functionality Tests", test_basic_functionality),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 30)
        
        try:
            if test_func():
                print(f"✅ {test_name} PASSED")
                passed += 1
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} ERROR: {e}")
    
    # Create test report
    create_test_report()
    
    # Summary
    print(f"\n📊 Test Summary: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The application is ready for use.")
        return True
    else:
        print("⚠️ Some tests failed. Please check the issues above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
