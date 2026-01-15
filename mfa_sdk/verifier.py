from mfa_sdk.crypto import CryptoUtils
import secrets
import string

class Verifier:
    def __init__(self, verifier_id):
        self.verifier_id = verifier_id
        self.user_registry = {} # Stores user_id -> public_key_pem

    def register_user(self, user_id, public_key_pem):
        """Registers a user's public key."""
        try:
            # Validate key
            CryptoUtils.load_public_key(public_key_pem)
            self.user_registry[user_id] = public_key_pem
            return True
        except Exception as e:
            print(f"Registration failed: {e}")
            return False

    def generate_otp(self, length=6):
        """Generates a cryptographically secure numeric OTP."""
        return ''.join(secrets.choice(string.digits) for _ in range(length))

    def encrypt_otp_for_user(self, user_id, otp):
        """
        Encrypts the OTP for the specific user.
        Returns the encrypted blob.
        """
        if user_id not in self.user_registry:
            raise Exception("User not found")

        pub_key_pem = self.user_registry[user_id]
        pub_key = CryptoUtils.load_public_key(pub_key_pem)

        return CryptoUtils.encrypt_data(pub_key, otp.encode('utf-8'))

    def verify_otp(self, original_otp, submitted_otp):
        """
        Verifies if the submitted OTP matches the original.
        In a real system, original_otp would be stored in a session.
        """
        return original_otp == submitted_otp
