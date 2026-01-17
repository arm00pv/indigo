<#
.SYNOPSIS
    Indigo MFA One-Click Installer for Windows
.DESCRIPTION
    Installs Python dependencies, initializes the database, creates a launcher, and configures the firewall.
    Must be run as Administrator.
#>

Write-Host "=== Indigo MFA Installer (Windows) ===" -ForegroundColor Cyan

# 0. Check Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator!"
    exit 1
}

# 1. Check Python
try {
    $pyVer = python --version 2>&1
    if ($pyVer -match "Python 3") {
        Write-Host "Found: $pyVer" -ForegroundColor Green
    } else {
        throw "Python 3 required."
    }
} catch {
    Write-Error "Python 3 not found in PATH. Please install Python 3.10+ from python.org and check 'Add to PATH'."
    exit 1
}

# 2. Setup Venv
$AppDir = Get-Location
Write-Host "Installation Directory: $AppDir"

if (-not (Test-Path "venv")) {
    Write-Host "Creating Virtual Environment..."
    python -m venv venv
}

# 3. Install Dependencies
Write-Host "Installing Dependencies..."
.\venv\Scripts\pip install -r requirements.txt

# 4. Configuration
$AdminKey = [Guid]::NewGuid().ToString().Replace("-", "")
Write-Host "Generated Admin Key: $AdminKey" -ForegroundColor Yellow

# 5. Initialize Database
Write-Host "Initializing Database..."
$env:FLASK_APP = "backend.app"
$env:ADMIN_API_KEY = $AdminKey
.\venv\Scripts\flask init-db

# 6. Create Launcher (Batch File on Desktop)
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$BatchPath = Join-Path $DesktopPath "Start-IndigoMFA.bat"

$BatchContent = @"
@echo off
cd /d "$AppDir"
set FLASK_APP=backend.app
set ADMIN_API_KEY=$AdminKey
echo === Indigo MFA ===
echo Admin Key: %ADMIN_API_KEY%
echo Dashboard: http://localhost:5000/dashboard
echo.
echo Starting Server...
.\venv\Scripts\flask run --host=0.0.0.0 --port=5000
pause
"@

Set-Content -Path $BatchPath -Value $BatchContent
Write-Host "Launcher created at: $BatchPath" -ForegroundColor Green

# 7. Configure Firewall
Write-Host "Configuring Firewall (Port 5000)..."
try {
    New-NetFirewallRule -DisplayName "Indigo MFA" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow -ErrorAction Stop
    Write-Host "Firewall Rule Added." -ForegroundColor Green
} catch {
    Write-Warning "Failed to add Firewall rule. You may need to allow Port 5000 manually."
}

Write-Host "`n=== Installation Complete! ===" -ForegroundColor Green
Write-Host "Double-click 'Start-IndigoMFA.bat' on your Desktop to run the server."
Write-Host "Admin Key: $AdminKey" -ForegroundColor Yellow
