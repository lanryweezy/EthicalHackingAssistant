@echo off
echo ====================================
echo Building Ethical Hacking Assistant
echo ====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo Python version:
python --version
echo.

REM Run the build script
echo Running build script...
python build.py

REM Check if build was successful
if exist "dist\EthicalHackingAssistant.exe" (
    echo.
    echo ====================================
    echo BUILD SUCCESSFUL!
    echo ====================================
    echo.
    echo Executable created: dist\EthicalHackingAssistant.exe
    echo.
    echo Testing the build...
    python test.py
    echo.
    echo You can now run the application with:
    echo   dist\EthicalHackingAssistant.exe
    echo.
    echo Or use the test script:
    echo   python test.py
    echo.
) else (
    echo.
    echo ====================================
    echo BUILD FAILED!
    echo ====================================
    echo.
    echo Please check the error messages above.
    echo.
)

pause
