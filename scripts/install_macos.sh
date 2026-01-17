#!/bin/bash

# Indigo MFA - macOS Installer
set -e

# Detect Directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="$REPO_ROOT"
ADMIN_KEY=$(openssl rand -hex 16)

echo "=== Indigo MFA Installer (macOS) ==="
echo "Installation Directory: $APP_DIR"

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "Python 3 not found. Installing via Homebrew..."
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Please install Homebrew first."
        exit 1
    fi
    brew install python
fi

# 2. Setup Venv
echo "Setting up Virtual Environment..."
cd "$APP_DIR"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
./venv/bin/pip install -r requirements.txt

# 3. Init DB
echo "Initializing Database..."
export FLASK_APP=backend.app
export ADMIN_API_KEY=$ADMIN_KEY
./venv/bin/flask init-db

# 4. Create Launch Agent (Auto-Start)
echo "Configuring Launch Agent..."
PLIST_PATH="$HOME/Library/LaunchAgents/com.indigo.mfa.plist"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.indigo.mfa</string>
    <key>ProgramArguments</key>
    <array>
        <string>$APP_DIR/venv/bin/gunicorn</string>
        <string>--workers</string>
        <string>1</string>
        <string>--bind</string>
        <string>0.0.0.0:5000</string>
        <string>backend.app:app</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$APP_DIR</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ADMIN_API_KEY</key>
        <string>$ADMIN_KEY</string>
        <key>FLASK_APP</key>
        <string>backend.app</string>
        <key>PYTHONPATH</key>
        <string>$APP_DIR</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$APP_DIR/app.log</string>
    <key>StandardErrorPath</key>
    <string>$APP_DIR/error.log</string>
</dict>
</plist>
EOF

# Load Agent
launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load "$PLIST_PATH"

echo "=== Installation Complete! ==="
echo "Service 'com.indigo.mfa' started."
echo "Dashboard: http://localhost:5000/dashboard"
echo "Admin Key: $ADMIN_KEY"
echo "Save this key!"
