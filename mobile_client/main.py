import sys
import os
import requests
import time
import json
import getpass
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mfa_sdk.authenticator import Authenticator
from mfa_sdk.crypto import CryptoUtils

# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Configuration
API_URLS = ["http://127.0.0.1:5000"] # Primary + Failovers
TENANT_ID = "default"

# Use Home Directory for storage
HOME_DIR = os.path.join(os.path.expanduser("~"), ".indigo-mfa")
if not os.path.exists(HOME_DIR):
    try:
        os.makedirs(HOME_DIR)
    except:
        pass # Fallback if permissions issue? Or just fail.

CONFIG_FILE = os.path.join(HOME_DIR, "client_config.json")
KEY_FILE = os.path.join(HOME_DIR, "device_key.pem")
PIN_FILE = os.path.join(HOME_DIR, "device_pin.txt")
DURESS_FILE = os.path.join(HOME_DIR, "device_duress.txt")
PUSH_PORT = 8089

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== {text} ==={Colors.ENDC}")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.FAIL}❌ {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.ENDC}")

def load_config():
    global API_URLS, TENANT_ID
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)

                # Handle legacy single URL or list
                if 'api_urls' in data:
                    API_URLS = data['api_urls']
                elif 'api_url' in data:
                    API_URLS = [data['api_url']]

                TENANT_ID = data.get('tenant_id', 'default')
                return data.get('user_id')
        except:
            print_error("Failed to load config.")
    return None

def save_config(user_id, urls, tenant_id):
    global API_URLS, TENANT_ID
    API_URLS = urls
    TENANT_ID = tenant_id
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump({
                "user_id": user_id,
                "api_urls": urls,
                "tenant_id": tenant_id
            }, f, indent=2)
        print_success("Configuration Saved.")
    except Exception as e:
        print_error(f"Failed to save config: {e}")

def send_request(method, endpoint, json_data=None):
    headers = {"X-Tenant-ID": TENANT_ID}

    last_error = None
    for base_url in API_URLS:
        url = f"{base_url.rstrip('/')}{endpoint}"
        try:
            if method == 'POST':
                return requests.post(url, json=json_data, headers=headers, timeout=5)
            elif method == 'GET':
                return requests.get(url, headers=headers, timeout=5)
        except Exception as e:
            print_info(f"Failed to connect to {base_url}, trying next...")
            last_error = e
            continue

    raise Exception(f"All endpoints failed. Last error: {last_error}")

def get_authenticator(user_id):
    auth = Authenticator(user_id)

    if os.path.exists(KEY_FILE) and os.path.exists(PIN_FILE):
        with open(KEY_FILE, "rb") as f:
            priv_pem = f.read()
        with open(PIN_FILE, "r") as f:
            pin = f.read().strip()

        from cryptography.hazmat.primitives import serialization
        try:
            auth._private_key = serialization.load_pem_private_key(priv_pem, password=None)
            auth._pin = pin
        except Exception:
            print_error("Key file corrupted or incompatible.")

        if os.path.exists(DURESS_FILE):
             with open(DURESS_FILE, "r") as f:
                auth._duress_pin = f.read().strip()

    else:
        from cryptography.hazmat.primitives import serialization
        print_info("No existing keys found. Creating new...")
        pin = input(f"{Colors.BOLD}Set a 4-digit PIN for your vault: {Colors.ENDC}")

        duress_pin = input(f"{Colors.BOLD}Set a 4-digit DURESS PIN (Optional, Press Enter to skip): {Colors.ENDC}")
        if not duress_pin:
             duress_pin = None

        auth.setup_account(pin, duress_pin)

        priv_pem = auth._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(KEY_FILE, "wb") as f:
            f.write(priv_pem)
        with open(PIN_FILE, "w") as f:
            f.write(pin)

        if duress_pin:
             with open(DURESS_FILE, "w") as f:
                  f.write(duress_pin)

    return auth

def register(auth):
    print_header("Registration")
    pub_key_pem = auth.get_public_key_pem()
    push_url = f"http://localhost:{PUSH_PORT}/push"

    payload = {
        "user_id": auth.user_id,
        "public_key_pem_hex": pub_key_pem.hex(),
        "push_endpoint": push_url
    }

    try:
        print_info(f"Registering User: {auth.user_id} (Tenant: {TENANT_ID})...")
        resp = send_request('POST', '/register', payload)

        if resp.status_code in [200, 201]:
            data = resp.json()
            print_success(f"{data['message']}")

            if "backup_codes" in data:
                print("\n" + Colors.WARNING + "⚠️  EMERGENCY BACKUP CODES - SAVE THESE NOW!" + Colors.ENDC)
                print(Colors.WARNING + "These codes allow you to login if you lose your device/PIN." + Colors.ENDC)
                print(Colors.WARNING + "They will ONLY be shown ONCE.\n" + Colors.ENDC)
                for code in data['backup_codes']:
                    print(f"  🔹 {Colors.BOLD}{code}{Colors.ENDC}")
                print("")
                input(f"{Colors.BLUE}Press Enter once you have saved them...{Colors.ENDC}")
        else:
            print_error(f"Error: {resp.text}")
    except Exception as e:
        print_error(f"{e}")

def login_with_backup_code(auth):
    print_header("Emergency Login (Backup Code)")
    code = input(f"{Colors.BOLD}Enter one of your 8-character Backup Codes: {Colors.ENDC}")

    if len(code) < 8:
        print_error("Invalid code length.")
        return

    try:
        print_info("Verifying Backup Code...")
        verify_resp = send_request('POST', '/auth/verify', {"user_id": auth.user_id, "otp": code})

        if verify_resp.status_code == 200:
            print_success("Authentication Successful! (Used Backup Code)")
        elif verify_resp.status_code == 403:
            msg = verify_resp.json().get('message')
            print_error(f"Security Alert: {msg}")
            if 'Retry-After' in verify_resp.headers:
                wait_time = verify_resp.headers['Retry-After']
                print(f"{Colors.WARNING}⏳ Please wait {wait_time} seconds before retrying.{Colors.ENDC}")
        else:
            print_error(f"Authentication Failed: {verify_resp.json().get('message')}")
    except Exception as e:
        print_error(f"{e}")

def setup_via_qr():
    print_header("QR / Smart Code Configuration")
    print("Paste the JSON payload or Smart Code from the Dashboard:")
    payload = input(f"{Colors.BOLD}> {Colors.ENDC}")

    import base64
    if not payload.strip().startswith("{"):
        try:
            decoded = base64.b64decode(payload).decode('utf-8')
            payload = decoded
            print_info("Decoded Smart Code.")
        except:
            pass

    try:
        data = json.loads(payload)
        uid = data.get('user_id')
        tid = data.get('tenant_id', 'default')

        # Handle single url vs list (for redundancy)
        urls = []
        if 'url' in data:
            urls.append(data['url'])
        if 'urls' in data:
            urls.extend(data['urls'])

        # Dedupe
        urls = list(dict.fromkeys(urls))

        if not urls or not uid:
            print_error("Invalid Payload: Missing url(s) or user_id")
            return None, None, None

        print_success(f"Configured for User: {uid} @ {urls} (Tenant: {tid})")
        return uid, urls, tid
    except Exception as e:
        print_error(f"Invalid Configuration: {e}")
        return None, None, None

def authenticate_flow(auth):
    print_header("Authentication")

    print_info("Requesting login challenge from server...")
    try:
        resp = send_request('POST', '/auth/challenge', {"user_id": auth.user_id})

        if resp.status_code == 403:
            print_error(f"Access Denied: {resp.json().get('error')}")
            if 'Retry-After' in resp.headers:
                wait_time = resp.headers['Retry-After']
                print(f"{Colors.WARNING}⏳ Please wait {wait_time} seconds before retrying.{Colors.ENDC}")
            return

        if resp.status_code != 200:
            print_error(f"Error getting challenge: {resp.text}")
            return

        data = resp.json()
        encrypted_hex = data["encrypted_challenge_hex"]
        encrypted_blob = bytes.fromhex(encrypted_hex)
        print_info(f"Received Encrypted Challenge ({len(encrypted_blob)} bytes)")

        pin = input(f"{Colors.BOLD}Enter PIN to decrypt: {Colors.ENDC}")
        try:
            # Decrypt returns tuple (otp, context)
            otp, context = auth.decrypt_otp(encrypted_blob, pin)

            # --- Context-Aware Auth Display ---
            if context:
                print(f"\n{Colors.WARNING}{Colors.BOLD}⚠️  ACTION REQUESTED: {context}{Colors.ENDC}")
                confirm = input(f"{Colors.BOLD}Do you verify this action? (y/N): {Colors.ENDC}")
                if confirm.lower() != 'y':
                    print_error("Authentication Cancelled by User.")
                    return
            else:
                print_success(f"Decrypted OTP: {Colors.BOLD}{otp}{Colors.ENDC}")

            print_info("Submitting OTP to server...")
            verify_resp = send_request('POST', '/auth/verify', {"user_id": auth.user_id, "otp": otp})

            if verify_resp.status_code == 200:
                print_success("Authentication Successful! Access Granted.")
            elif verify_resp.status_code == 403:
                msg = verify_resp.json().get('message')
                print_error(f"Security Alert: {msg}")
                if 'Retry-After' in verify_resp.headers:
                    wait_time = verify_resp.headers['Retry-After']
                    print(f"{Colors.WARNING}⏳ Please wait {wait_time} seconds before retrying.{Colors.ENDC}")
            else:
                print_error(f"Authentication Failed: {verify_resp.json().get('message')}")

        except Exception as e:
            print_error(f"Decryption Failed (Wrong PIN?): {e}")

    except Exception as e:
        print_error(f"{e}")

# --- Push Listener ---
class PushHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/push':
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            data = json.loads(body)

            print(f"\n{Colors.WARNING}🔔 PUSH NOTIFICATION RECEIVED! {Colors.ENDC}")
            print(f"{Colors.BOLD}Challenge Blob:{Colors.ENDC} {data.get('encrypted_challenge_hex')[:20]}...")
            print(f"{Colors.BLUE}Use option '2' to login now.{Colors.ENDC}")

            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return # Silence server logs

def start_push_listener():
    server = HTTPServer(('localhost', PUSH_PORT), PushHandler)
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()

def main():
    start_push_listener()
    print(f"\n{Colors.CYAN}{Colors.BOLD}📱 Indigo MFA Client v1.3 (Redundant){Colors.ENDC}")

    # Auto-load config
    user_id = load_config()
    if user_id:
        print_info(f"Loaded configuration for User: {user_id} (Tenant: {TENANT_ID})")
        print_info(f"Endpoints: {API_URLS}")
    else:
        user_id = input("Enter your User ID (email): ")

    try:
        auth = get_authenticator(user_id)
    except KeyboardInterrupt:
        return

    while True:
        print(f"\n{Colors.HEADER}--- Menu ---{Colors.ENDC}")
        print("1. Register with Server")
        print("2. Login (Receive & Decrypt Challenge)")
        print("3. Login with Backup Code")
        print("4. Setup via Smart Code / QR")
        print("5. Exit")
        choice = input(f"{Colors.BOLD}Select: {Colors.ENDC}")

        if choice == "1":
            register(auth)
        elif choice == "2":
            authenticate_flow(auth)
        elif choice == "3":
            login_with_backup_code(auth)
        elif choice == "4":
             uid, urls, tid = setup_via_qr()
             if uid:
                 save_config(uid, urls, tid)
                 # Re-init Auth
                 auth = get_authenticator(uid)
                 print_info("Configuration updated.")
        elif choice == "5":
            print("Bye!")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
