import sys
import os
import requests
import time
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mfa_sdk.authenticator import Authenticator
from mfa_sdk.crypto import CryptoUtils

API_URL = "http://127.0.0.1:5000"
KEY_FILE = "device_key.pem"
PIN_FILE = "device_pin.txt" # Insecure for demo, in real mobile app use SecureStorage

def get_authenticator(user_id):
    auth = Authenticator(user_id)

    # Load existing key if present
    if os.path.exists(KEY_FILE) and os.path.exists(PIN_FILE):
        with open(KEY_FILE, "rb") as f:
            priv_pem = f.read()
        with open(PIN_FILE, "r") as f:
            pin = f.read().strip()

        # Manually load key into authenticator (Simulating secure load)
        from cryptography.hazmat.primitives import serialization
        auth._private_key = serialization.load_pem_private_key(priv_pem, password=None)
        auth._pin = pin
    else:
        # Setup new
        from cryptography.hazmat.primitives import serialization
        print("No existing account found. Creating new...")
        pin = input("Set a 4-digit PIN: ")
        auth.setup_account(pin)

        # Save key
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
    print("\n--- Registration ---")
    pub_key_pem = auth.get_public_key_pem()
    payload = {
        "user_id": auth.user_id,
        "public_key_pem_hex": pub_key_pem.hex()
    }

    try:
        resp = requests.post(f"{API_URL}/register", json=payload)
        if resp.status_code in [200, 201]:
            print(f"✅ Success: {resp.json()['message']}")
        else:
            print(f"❌ Error: {resp.text}")
    except Exception as e:
        print(f"❌ Network Error: {e}")

def authenticate_flow(auth):
    print("\n--- Authentication ---")

    # 1. Trigger Challenge (Usually triggered by Web, but here we trigger it to get the blob)
    print("Requesting login challenge from server...")
    try:
        resp = requests.post(f"{API_URL}/auth/challenge", json={"user_id": auth.user_id})
        if resp.status_code != 200:
            print(f"❌ Error getting challenge: {resp.text}")
            return

        data = resp.json()
        encrypted_hex = data["encrypted_challenge_hex"]
        encrypted_blob = bytes.fromhex(encrypted_hex)
        print(f"📥 Received Encrypted Challenge ({len(encrypted_blob)} bytes)")

        # 2. Decrypt
        pin = input("Enter PIN to decrypt: ")
        try:
            otp = auth.decrypt_otp(encrypted_blob, pin)
            print(f"🔓 Decrypted OTP: {otp}")

            # 3. Submit (Simulating User typing it into the web portal)
            print("Submitting OTP to server...")
            verify_resp = requests.post(f"{API_URL}/auth/verify", json={"user_id": auth.user_id, "otp": otp})

            if verify_resp.status_code == 200:
                print("✅ Authentication Successful!")
            else:
                print("❌ Authentication Failed!")

        except Exception as e:
            print(f"❌ Decryption Failed: {e}")

    except Exception as e:
        print(f"❌ Network Error: {e}")

def main():
    print("📱 Mobile MFA Client Simulator")
    user_id = input("Enter your User ID (email): ")
    auth = get_authenticator(user_id)

    while True:
        print("\n1. Register with Server")
        print("2. Login (Receive & Decrypt Challenge)")
        print("3. Exit")
        choice = input("Select: ")

        if choice == "1":
            register(auth)
        elif choice == "2":
            authenticate_flow(auth)
        elif choice == "3":
            break

if __name__ == "__main__":
    main()
