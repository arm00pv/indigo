#!/bin/bash

# Indigo MFA - Smart Installer v2.0
# Supported: Ubuntu 20.04/22.04, Debian 11/12

set -e

# Default Configuration
DOMAIN="localhost"
EMAIL=""
INTERACTIVE=true
SKIP_UFW=false
SKIP_SSL=false

# Detect Script Location (Repo Root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="$REPO_ROOT"
SERVICE_NAME="indigo-mfa"
ADMIN_KEY=$(openssl rand -hex 16)

# Parse Arguments
while getopts "d:e:yus" opt; do
  case $opt in
    d) DOMAIN="$OPTARG" ;;
    e) EMAIL="$OPTARG" ;;
    y) INTERACTIVE=false ;;
    u) SKIP_UFW=true ;;
    s) SKIP_SSL=true ;;
    *) echo "Usage: $0 [-d domain] [-e email] [-y (yes to all)] [-u (skip ufw)] [-s (skip ssl)]"; exit 1 ;;
  esac
done

echo "=== Indigo MFA Installer v2.0 ==="
echo "Domain: $DOMAIN"
echo "Installation Directory: $APP_DIR"

# 1. Install Dependencies
echo "[1/7] Installing System Dependencies..."
sudo apt-get update -qq
sudo apt-get install -y python3 python3-pip python3-venv apache2 libapache2-mod-wsgi-py3 git certbot python3-certbot-apache ufw

# 2. Permissions Setup
echo "[2/7] Configuring Permissions for www-data..."
sudo chown -R www-data:www-data "$APP_DIR"

# 3. Setup Python Environment
echo "[3/7] Setting up Python Virtualenv..."
cd "$APP_DIR"
if [ ! -d "venv" ]; then
    sudo -u www-data python3 -m venv venv
fi
sudo -u www-data ./venv/bin/pip install -r requirements.txt

# 4. Create Systemd Service (Gunicorn)
echo "[4/7] Creating Systemd Service..."
sudo tee /etc/systemd/system/$SERVICE_NAME.service > /dev/null <<EOF
[Unit]
Description=Indigo MFA Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
Environment="PYTHONPATH=$APP_DIR"
Environment="FLASK_APP=backend.app"
Environment="ADMIN_API_KEY=$ADMIN_KEY"
# Environment="ALERT_WEBHOOK_URL="
ExecStartPre=$APP_DIR/venv/bin/flask init-db
# Using 1 worker to ensure SQLite safety (database locking). Increase if using PostgreSQL.
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 1 --bind unix:$APP_DIR/indigo.sock -m 007 backend.app:app

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME

# 5. Configure Firewall (UFW)
if [ "$SKIP_UFW" = false ]; then
    echo "[5/7] Configuring UFW Firewall..."
    sudo ufw allow ssh
    sudo ufw allow http
    sudo ufw allow https
    # Deny direct access to port 5000 (if it were exposed, but we use socket)
    # sudo ufw deny 5000
    # Enable UFW non-interactively? Risk of locking out SSH if not allowed.
    # We allowed ssh above.
    if [ "$INTERACTIVE" = true ]; then
        read -p "Enable UFW now? (y/N): " UFW_CONFIRM
        if [[ $UFW_CONFIRM =~ ^[Yy]$ ]]; then
            sudo ufw --force enable
        fi
    else
        sudo ufw --force enable
    fi
else
    echo "[5/7] Skipping Firewall configuration."
fi

# 6. Configure Apache
echo "[6/7] Configuring Apache..."
sudo a2enmod proxy proxy_http ssl rewrite headers

# Define the VHost Block content
VHOST_CONTENT="
# --- Indigo MFA Configuration ---
<VirtualHost *:80>
    ServerName $DOMAIN

    ProxyPreserveHost On
    ProxyPass / unix:$APP_DIR/indigo.sock|http://127.0.0.1/
    ProxyPassReverse / unix:$APP_DIR/indigo.sock|http://127.0.0.1/

    ErrorLog \${APACHE_LOG_DIR}/indigo_error.log
    CustomLog \${APACHE_LOG_DIR}/indigo_access.log combined
</VirtualHost>
# ------------------------------
"

TARGET_CONF="/etc/apache2/sites-available/indigo.conf"

if [ "$INTERACTIVE" = true ]; then
    echo ""
    read -p "Enter path to existing Apache config to append to (Press Enter to create new $TARGET_CONF): " EXISTING_CONF
else
    EXISTING_CONF=""
fi

if [ -z "$EXISTING_CONF" ]; then
    # Create New File
    echo "Creating new config at $TARGET_CONF"
    echo "$VHOST_CONTENT" | sudo tee "$TARGET_CONF" > /dev/null

    sudo a2dissite 000-default.conf || true
    sudo a2ensite indigo.conf
else
    # Append to Existing
    if [ -f "$EXISTING_CONF" ]; then
        echo "Backing up $EXISTING_CONF..."
        sudo cp "$EXISTING_CONF" "$EXISTING_CONF.bak"
        echo "$VHOST_CONTENT" | sudo tee -a "$EXISTING_CONF" > /dev/null
    else
        echo "Error: File $EXISTING_CONF not found. Skipping Apache config."
    fi
fi

sudo systemctl restart apache2

# 7. SSL (Certbot)
if [ "$SKIP_SSL" = false ] && [ "$DOMAIN" != "localhost" ]; then
    echo "[7/7] Configuring SSL with Certbot..."
    if [ -z "$EMAIL" ] && [ "$INTERACTIVE" = true ]; then
        read -p "Enter Email for Let's Encrypt updates: " EMAIL
    fi

    if [ -n "$EMAIL" ]; then
        sudo certbot --apache -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
    else
        echo "Skipping SSL: No email provided."
    fi
else
    echo "[7/7] Skipping SSL configuration."
fi

echo "=== Installation Complete! ==="
echo "Dashboard: http://$DOMAIN/dashboard"
echo "Admin Key: $ADMIN_KEY"
echo "Save this key! It is stored in /etc/systemd/system/$SERVICE_NAME.service"
