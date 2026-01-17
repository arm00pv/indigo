#!/bin/bash

# Indigo MFA - Smart Installer v3.0
# Supported: Ubuntu 20.04/22.04, Debian 11/12

set -e

# Default Configuration
DOMAIN="localhost"
EMAIL=""
INTERACTIVE=true
SKIP_UFW=false
SKIP_SSL=false
ROLE="validator" # validator | enterprise | user
BACKUP_CRON=false
UNINSTALL=false

# Detect Script Location (Repo Root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="$REPO_ROOT"
SERVICE_NAME="indigo-mfa"
ADMIN_KEY=$(openssl rand -hex 16)

# Help
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -r <role>       Installation Role: validator (default), enterprise, user"
    echo "  -d <domain>     Domain Name (e.g., auth.example.com)"
    echo "  -e <email>      Email for SSL (Let's Encrypt)"
    echo "  -b              Enable Daily Backups"
    echo "  -y              Non-interactive mode (Yes to all)"
    echo "  -u              Skip UFW Firewall"
    echo "  -s              Skip SSL Configuration"
    echo "  --uninstall     Uninstall Indigo MFA"
    exit 1
}

# Parse Arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -r|--role)
      ROLE="$2"
      shift 2
      ;;
    -d|--domain)
      DOMAIN="$2"
      shift 2
      ;;
    -e|--email)
      EMAIL="$2"
      shift 2
      ;;
    -b|--backup)
      BACKUP_CRON=true
      shift
      ;;
    -y|--yes)
      INTERACTIVE=false
      shift
      ;;
    -u|--skip-ufw)
      SKIP_UFW=true
      shift
      ;;
    -s|--skip-ssl)
      SKIP_SSL=true
      shift
      ;;
    --uninstall)
      UNINSTALL=true
      shift
      ;;
    *)
      usage
      ;;
  esac
done

# Uninstall Logic
if [ "$UNINSTALL" = true ]; then
    echo "!!! UNINSTALLING INDIGO MFA !!!"
    if [ "$INTERACTIVE" = true ]; then
        read -p "Are you sure? This will delete data! (y/N): " CONFIRM
        if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then exit 0; fi
    fi
    sudo systemctl stop $SERVICE_NAME || true
    sudo systemctl disable $SERVICE_NAME || true
    sudo rm /etc/systemd/system/$SERVICE_NAME.service || true
    sudo systemctl daemon-reload
    sudo a2dissite indigo.conf || true
    sudo systemctl restart apache2
    echo "Service removed. Files in $APP_DIR remain."
    exit 0
fi

# Zero-Config Wizard
if [ "$INTERACTIVE" = true ] && [ "$DOMAIN" = "localhost" ] && [ "$ROLE" = "validator" ]; then
    echo "=== Indigo MFA Installer Wizard ==="
    echo "1. Validator Node (Standard Server)"
    echo "2. Enterprise Cluster (PostgreSQL + High Performance)"
    echo "3. User Client (CLI Tool only)"
    read -p "Select Installation Type [1]: " SELECTION
    case $SELECTION in
        2) ROLE="enterprise" ;;
        3) ROLE="user" ;;
        *) ROLE="validator" ;;
    esac

    if [ "$ROLE" != "user" ]; then
        read -p "Enter Domain Name [localhost]: " IN_DOMAIN
        if [ -n "$IN_DOMAIN" ]; then DOMAIN="$IN_DOMAIN"; fi
    fi
fi

# --- User Client Installation ---
if [ "$ROLE" = "user" ]; then
    echo "[User Mode] Installing CLI Client..."
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip python3-venv

    cd "$APP_DIR"
    if [ ! -d "venv" ]; then python3 -m venv venv; fi
    ./venv/bin/pip install -r requirements.txt

    # Create Wrapper
    WRAPPER="/usr/local/bin/indigo-mfa"
    echo "#!/bin/bash" | sudo tee $WRAPPER > /dev/null
    echo "cd $APP_DIR" | sudo tee -a $WRAPPER > /dev/null
    echo "./venv/bin/python mobile_client/main.py" | sudo tee -a $WRAPPER > /dev/null
    sudo chmod +x $WRAPPER

    echo "=== Client Installed ==="
    echo "Run 'indigo-mfa' to start."
    exit 0
fi

# --- Server Installation (Validator / Enterprise) ---

echo "=== Installing $ROLE Node ==="
echo "Domain: $DOMAIN"
echo "Installation Directory: $APP_DIR"

# 1. Install Dependencies
echo "[1/8] Installing System Dependencies..."
PKGS="python3 python3-pip python3-venv apache2 libapache2-mod-wsgi-py3 git certbot python3-certbot-apache ufw"
if [ "$ROLE" = "enterprise" ]; then
    PKGS="$PKGS postgresql postgresql-contrib"
fi
sudo apt-get update -qq
sudo apt-get install -y $PKGS

# 2. Permissions
echo "[2/8] Configuring Permissions..."
sudo chown -R www-data:www-data "$APP_DIR"

# 3. Python Env
echo "[3/8] Setting up Python..."
cd "$APP_DIR"
if [ ! -d "venv" ]; then
    sudo -u www-data python3 -m venv venv
fi
sudo -u www-data ./venv/bin/pip install -r requirements.txt

# 4. Database Setup
DB_URL="sqlite:///$APP_DIR/backend/mfa.db"
WORKERS=1

if [ "$ROLE" = "enterprise" ]; then
    echo "[Enterprise] Configuring PostgreSQL..."
    # Create DB user/pass if not exists
    sudo -u postgres psql -c "CREATE USER indigo WITH PASSWORD 'indigo_secure_pass';" || true
    sudo -u postgres psql -c "CREATE DATABASE indigo_mfa OWNER indigo;" || true
    DB_URL="postgresql://indigo:indigo_secure_pass@localhost/indigo_mfa"
    WORKERS=4 # Higher concurrency for Postgres
fi

# 5. Systemd Service
echo "[5/8] Creating Systemd Service..."
sudo tee /etc/systemd/system/$SERVICE_NAME.service > /dev/null <<EOF
[Unit]
Description=Indigo MFA Backend ($ROLE)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
Environment="PYTHONPATH=$APP_DIR"
Environment="FLASK_APP=backend.app"
Environment="ADMIN_API_KEY=$ADMIN_KEY"
Environment="DATABASE_URL=$DB_URL"
ExecStartPre=$APP_DIR/venv/bin/flask init-db
ExecStart=$APP_DIR/venv/bin/gunicorn --workers $WORKERS --bind unix:$APP_DIR/indigo.sock -m 007 backend.app:app

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME

# 6. Firewall
if [ "$SKIP_UFW" = false ]; then
    echo "[6/8] Configuring UFW..."
    sudo ufw allow ssh
    sudo ufw allow http
    sudo ufw allow https
    if [ "$INTERACTIVE" = true ]; then
        read -p "Enable UFW now? (y/N): " UFW_CONFIRM
        if [[ $UFW_CONFIRM =~ ^[Yy]$ ]]; then sudo ufw --force enable; fi
    else
        sudo ufw --force enable
    fi
else
    echo "[6/8] Skipping Firewall."
fi

# 7. Apache
echo "[7/8] Configuring Apache..."
sudo a2enmod proxy proxy_http ssl rewrite headers

VHOST_CONTENT="
<VirtualHost *:80>
    ServerName $DOMAIN
    ProxyPreserveHost On
    ProxyPass / unix:$APP_DIR/indigo.sock|http://127.0.0.1/
    ProxyPassReverse / unix:$APP_DIR/indigo.sock|http://127.0.0.1/
    ErrorLog \${APACHE_LOG_DIR}/indigo_error.log
    CustomLog \${APACHE_LOG_DIR}/indigo_access.log combined
</VirtualHost>
"
TARGET_CONF="/etc/apache2/sites-available/indigo.conf"

if [ -z "$EXISTING_CONF" ]; then
    echo "$VHOST_CONTENT" | sudo tee "$TARGET_CONF" > /dev/null
    sudo a2dissite 000-default.conf || true
    sudo a2ensite indigo.conf
fi
sudo systemctl restart apache2

# 8. SSL & Backup
if [ "$SKIP_SSL" = false ] && [ "$DOMAIN" != "localhost" ]; then
    echo "[8/8] Configuring SSL..."
    if [ -z "$EMAIL" ] && [ "$INTERACTIVE" = true ]; then
        read -p "Enter Email for Certbot: " EMAIL
    fi
    if [ -n "$EMAIL" ]; then
        sudo certbot --apache -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect
    fi
fi

if [ "$BACKUP_CRON" = true ]; then
    echo "Setting up Daily Backup Cron..."
    # Run at 2 AM
    (crontab -l 2>/dev/null; echo "0 2 * * * cd $APP_DIR && ./venv/bin/flask backup >> /var/log/indigo_backup.log 2>&1") | crontab -
fi

echo "=== Installation Complete ($ROLE) ==="
echo "Dashboard: http://$DOMAIN/dashboard"
echo "Admin Key: $ADMIN_KEY"
echo "Save this key!"
