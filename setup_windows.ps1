# Setup script for White Hat on Windows
# Run this script in PowerShell with Administrator privileges

# Check if Python is installed
try {
    $pythonVersion = python --version
    Write-Host "Python detected: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found. Please install Python 3.8 or later from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "After installing Python, run this script again." -ForegroundColor Yellow
    exit 1
}

# Check if Rust is installed
try {
    $rustVersion = rustc --version
    Write-Host "Rust detected: $rustVersion" -ForegroundColor Green
} catch {
    Write-Host "Rust not found. Installing Rust..." -ForegroundColor Yellow
    
    # Download and run the Rust installer
    $rustupInit = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile $rustupInit
    
    # Run the installer
    & $rustupInit -y
    
    # Add Rust to the current session's PATH
    $env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
    
    # Verify installation
    $rustVersion = rustc --version
    Write-Host "Rust installed: $rustVersion" -ForegroundColor Green
}

# Install Python dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Build the Rust application
Write-Host "Building Rust application..." -ForegroundColor Yellow
cargo build --release

# Check if nmap is installed
try {
    $nmapVersion = nmap --version
    Write-Host "Nmap detected: $nmapVersion" -ForegroundColor Green
} catch {
    Write-Host "Nmap not found. For network scanning capabilities, download and install nmap from:" -ForegroundColor Yellow
    Write-Host "https://nmap.org/download.html" -ForegroundColor Cyan
}

# Prompt for LLM API key
Write-Host "`nWould you like to set up the LLM API key for AI capabilities? (y/n)" -ForegroundColor Yellow
$setupApiKey = Read-Host

if ($setupApiKey -eq "y" -or $setupApiKey -eq "Y") {
    Write-Host "Enter your API key for the LLM service:" -ForegroundColor Yellow
    $apiKey = Read-Host -AsSecureString
    
    # Convert the secure string to plain text (for setting the environment variable)
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($apiKey)
    $plainApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    # Set the environment variable for the current user
    [System.Environment]::SetEnvironmentVariable("LLM_API_KEY", $plainApiKey, "User")
    
    # Also set for the current session
    $env:LLM_API_KEY = $plainApiKey
    
    Write-Host "API key has been set as an environment variable (LLM_API_KEY) for the current user." -ForegroundColor Green
} else {
    Write-Host "Skipping API key setup. You can set it later using:" -ForegroundColor Yellow
    Write-Host '$env:LLM_API_KEY = "your-api-key-here"' -ForegroundColor Cyan
    Write-Host "Or set it permanently for your user account with:" -ForegroundColor Yellow
    Write-Host '[System.Environment]::SetEnvironmentVariable("LLM_API_KEY", "your-api-key-here", "User")' -ForegroundColor Cyan
}

# Create .cache directory for LLM responses
New-Item -ItemType Directory -Path ".cache\llm" -Force | Out-Null

Write-Host "`nSetup complete! You can now use White Hat." -ForegroundColor Green
Write-Host "To run the application:" -ForegroundColor Yellow
Write-Host ".\target\release\white_hat [COMMAND]" -ForegroundColor Cyan
Write-Host "`nOr during development:" -ForegroundColor Yellow
Write-Host "cargo run -- [COMMAND]" -ForegroundColor Cyan
Write-Host "`nFor available commands, see the README.md file." -ForegroundColor Yellow
