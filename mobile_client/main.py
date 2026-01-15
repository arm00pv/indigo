import sys
import os
import requests
import time
import json
import getpass

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

API_URL = "http://127.0.0.1:5000"
KEY_FILE = "device_key.pem"
PIN_FILE = "device_pin.txt" # Insecure for demo

def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== {text} ==={Colors.ENDC}")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.FAIL}❌ {text}{Colors.ENDC}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.ENDC}")

def get_authenticator(user_id):
    auth = Authenticator(user_id)

    if os.path.exists(KEY_FILE) and os.path.exists(PIN_FILE):
        with open(KEY_FILE, "rb") as f:
            priv_pem = f.read()
        with open(PIN_FILE, "r") as f:
            pin = f.read().strip()

        from cryptography.hazmat.primitives import serialization
        auth._private_key = serialization.load_pem_private_key(priv_pem, password=None)
        auth._pin = pin
    else:
        from cryptography.hazmat.primitives import serialization
        print_info("No existing account found. Creating new...")
        pin = input(f"{Colors.BOLD}Set a 4-digit PIN for your vault: {Colors.ENDC}")
        auth.setup_account(pin)

        priv_pem = auth._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(KEY_FILE, "wb") as f:
            f.write(priv_pem)
        with open(PIN_FILE, "w") as f:
            f.write(pin)

    return auth

def register(auth):
    print_header("Registration")
    pub_key_pem = auth.get_public_key_pem()
    payload = {
        "user_id": auth.user_id,
        "public_key_pem_hex": pub_key_pem.hex()
    }

    try:
        print_info(f"Registering User: {auth.user_id}...")
        resp = requests.post(f"{API_URL}/register", json=payload)
        if resp.status_code in [200, 201]:
            print_success(f"{resp.json()['message']}")
        else:
            print_error(f"Error: {resp.text}")
    except Exception as e:
        print_error(f"Network Error: {e}")

def authenticate_flow(auth):
    print_header("Authentication")

    print_info("Requesting login challenge from server...")
    try:
        resp = requests.post(f"{API_URL}/auth/challenge", json={"user_id": auth.user_id})

        if resp.status_code == 403:
            print_error(f"Access Denied: {resp.json().get('error')}")
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
            otp = auth.decrypt_otp(encrypted_blob, pin)
            print_success(f"Decrypted OTP: {Colors.BOLD}{otp}{Colors.ENDC}")

            print_info("Submitting OTP to server...")
            verify_resp = requests.post(f"{API_URL}/auth/verify", json={"user_id": auth.user_id, "otp": otp})

            if verify_resp.status_code == 200:
                print_success("Authentication Successful! Access Granted.")
            elif verify_resp.status_code == 403:
                print_error(f"Security Alert: {verify_resp.json().get('message')}")
            else:
                print_error(f"Authentication Failed: {verify_resp.json().get('message')}")

        except Exception as e:
            print_error(f"Decryption Failed (Wrong PIN?): {e}")

    except Exception as e:
        print_error(f"Network Error: {e}")

def main():
    print(f"\n{Colors.CYAN}{Colors.BOLD}📱 Mobile MFA Client Simulator v2.0{Colors.ENDC}")
    user_id = input("Enter your User ID (email): ")
    try:
        auth = get_authenticator(user_id)
    except KeyboardInterrupt:
        return

    while True:
        print(f"\n{Colors.HEADER}--- Menu ---{Colors.ENDC}")
        print("1. Register with Server")
        print("2. Login (Receive & Decrypt Challenge)")
        print("3. Exit")
        choice = input(f"{Colors.BOLD}Select: {Colors.ENDC}")

        if choice == "1":
            register(auth)
        elif choice == "2":
            authenticate_flow(auth)
        elif choice == "3":
            print("Bye!")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
