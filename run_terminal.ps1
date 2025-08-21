# PowerShell script to run Ethical Hacking Assistant in Windows Terminal
param(
    [switch]$InstallDeps = $false
)

# Set window title
$Host.UI.RawUI.WindowTitle = "Ethical Hacking Assistant"

# Set colors for better visibility
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "Green"

# Clear the screen
Clear-Host

# Display banner
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "    Ethical Hacking Assistant Terminal      " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Install dependencies if requested
if ($InstallDeps) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    try {
        python -m pip install -r requirements.txt
        Write-Host "Dependencies installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Error installing dependencies: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please install dependencies manually using: python -m pip install -r requirements.txt" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Python version: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found. Please install Python and add it to your PATH." -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host ""
Write-Host "Starting Ethical Hacking Assistant..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to exit the application." -ForegroundColor Gray
Write-Host ""

# Run the main application
try {
    python main.py
} catch {
    Write-Host ""
    Write-Host "Error running application: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Application terminated." -ForegroundColor Yellow
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
