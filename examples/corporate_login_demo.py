import sys
import os

# Ensure we can import the SDK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mfa_sdk.authenticator import Authenticator
from mfa_sdk.verifier import Verifier

def run_corporate_login_demo():
    print("=== Corporate Secure Login System Demo (Decentralized MFA SDK) ===\n")

    # 1. System Initialization
    corporate_system = Verifier(verifier_id="Corp-SSO-System")
    print("[System] SSO Verifier initialized.")

    # 2. User Onboarding (Registration)
    user_email = "employee@company.com"
    print(f"\n[Onboarding] Registering new employee: {user_email}")

    # User sets up their Authenticator App
    user_app = Authenticator(user_email)
    user_app.setup_account(pin="9999")

    # Exchange Public Key
    user_pub_key = user_app.get_public_key_pem()
    corporate_system.register_user(user_email, user_pub_key)
    print(f"[Onboarding] User Public Key registered in Corporate Directory.")

    # 3. Login Flow
    print(f"\n[Login] User {user_email} attempts to log in to Employee Portal.")

    # System generates secure OTP
    otp = corporate_system.generate_otp()
    print(f"[System] Generated Secure Code: [HIDDEN]") # In real log, don't show it.

    # System encrypts OTP for this specific user
    print(f"[System] Encrypting Code with User's Public Key...")
    encrypted_challenge = corporate_system.encrypt_otp_for_user(user_email, otp)
    print(f"[Network] Sending encrypted payload ({len(encrypted_challenge)} bytes) to User App.")

    # 4. User Authentication (Decryption)
    print(f"\n[User App] Received login challenge.")
    try:
        # User enters PIN to unlock their key and decrypt the message
        entered_pin = "9999" # Correct PIN
        decrypted_code = user_app.decrypt_otp(encrypted_challenge, entered_pin)
        print(f"[User App] PIN Correct. Decrypted Code: {decrypted_code}")

        # User submits the code to the portal
        print(f"[User Action] Submitting code '{decrypted_code}' to System...")

        if corporate_system.verify_otp(otp, decrypted_code):
            print(f"\n✅ [System] ACCESS GRANTED. Welcome, {user_email}!")
        else:
            print(f"\n❌ [System] ACCESS DENIED. Invalid Code.")

    except Exception as e:
        print(f"❌ [Error] {e}")

    # 5. Invalid PIN Scenario
    print(f"\n[Scenario] User enters wrong PIN...")
    try:
        user_app.decrypt_otp(encrypted_challenge, "0000")
    except Exception as e:
        print(f"✅ [Security] Blocked: {e}")

if __name__ == "__main__":
    run_corporate_login_demo()
