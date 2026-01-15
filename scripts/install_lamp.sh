#!/bin/bash

# Indigo MFA - One-Click LAMP Installer
# Supported: Ubuntu 20.04/22.04, Debian 11/12

set -e

# Configuration
APP_DIR="/var/www/indigo-mfa"
SERVICE_NAME="indigo-mfa"
DOMAIN="localhost" # Change this to your domain
ADMIN_KEY="change-me-immediately"

echo "=== Indigo MFA Installer ==="

# 1. Install Dependencies
echo "[1/6] Installing System Dependencies..."
sudo apt-get update -qq
sudo apt-get install -y python3 python3-pip python3-venv apache2 libapache2-mod-wsgi-py3 git

# 2. Setup Project Directory
echo "[2/6] Setting up Directory at $APP_DIR..."
sudo mkdir -p $APP_DIR
# Copy current directory contents to APP_DIR (Assuming script runs from repo root)
# In a real one-click, this might git clone
sudo cp -r . $APP_DIR
sudo chown -R www-data:www-data $APP_DIR

# 3. Setup Python Environment
echo "[3/6] Setting up Python Virtualenv..."
cd $APP_DIR
sudo -u www-data python3 -m venv venv
sudo -u www-data ./venv/bin/pip install -r requirements.txt

# 4. Create Systemd Service (Gunicorn)
echo "[4/6] Creating Systemd Service..."
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
Environment="ADMIN_API_KEY=$ADMIN_KEY"
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 3 --bind unix:indigo.sock -m 007 backend.app:app

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME

# 5. Configure Apache
echo "[5/6] Configuring Apache..."
sudo a2enmod proxy proxy_http

sudo tee /etc/apache2/sites-available/indigo.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN

    ProxyPreserveHost On
    ProxyPass / unix:$APP_DIR/indigo.sock|http://127.0.0.1/
    ProxyPassReverse / unix:$APP_DIR/indigo.sock|http://127.0.0.1/

    ErrorLog \${APACHE_LOG_DIR}/indigo_error.log
    CustomLog \${APACHE_LOG_DIR}/indigo_access.log combined
</VirtualHost>
EOF

sudo a2dissite 000-default.conf
sudo a2ensite indigo.conf
sudo systemctl restart apache2

echo "=== Installation Complete! ==="
echo "Dashboard: http://$DOMAIN/dashboard"
echo "Admin Key: $ADMIN_KEY"
echo "Please secure your server and update the ADMIN_KEY in /etc/systemd/system/$SERVICE_NAME.service"
