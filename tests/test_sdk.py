import pytest
from mfa_sdk.authenticator import Authenticator
from mfa_sdk.verifier import Verifier
from mfa_sdk.crypto import CryptoUtils

class TestMFASDK:

    @pytest.fixture
    def authenticator(self):
        auth = Authenticator("test_user")
        auth.setup_account(pin="1234")
        return auth

    @pytest.fixture
    def verifier(self):
        return Verifier(verifier_id="test_verifier")

    def test_end_to_end_flow(self, verifier, authenticator):
        # Register
        pub_key = authenticator.get_public_key_pem()
        verifier.register_user(authenticator.user_id, pub_key)

        # Generate and Encrypt OTP
        original_otp = verifier.generate_otp()
        encrypted = verifier.encrypt_otp_for_user(authenticator.user_id, original_otp)

        # User Decrypts
        decrypted_otp, context = authenticator.decrypt_otp(encrypted, pin="1234")

        # Verify
        assert context is None
        assert decrypted_otp == original_otp
        assert verifier.verify_otp(original_otp, decrypted_otp)

    def test_context_aware_auth(self, verifier, authenticator):
        pub_key = authenticator.get_public_key_pem()
        verifier.register_user(authenticator.user_id, pub_key)

        original_otp = "123456"
        ctx_msg = "Transfer $500"
        encrypted = verifier.encrypt_otp_for_user(authenticator.user_id, original_otp, context=ctx_msg)

        decrypted_otp, context = authenticator.decrypt_otp(encrypted, pin="1234")

        assert decrypted_otp == original_otp
        assert context == ctx_msg

    def test_wrong_pin(self, verifier, authenticator):
        pub_key = authenticator.get_public_key_pem()
        verifier.register_user(authenticator.user_id, pub_key)

        otp = "123456"
        encrypted = verifier.encrypt_otp_for_user(authenticator.user_id, otp)

        with pytest.raises(Exception, match="Invalid PIN"):
            authenticator.decrypt_otp(encrypted, pin="9999")

    def test_encryption_integrity(self, verifier, authenticator):
        """Ensure modified ciphertext fails decryption."""
        pub_key = authenticator.get_public_key_pem()
        verifier.register_user(authenticator.user_id, pub_key)

        encrypted = verifier.encrypt_otp_for_user(authenticator.user_id, "123456")

        # Tamper with the last byte (tag or ciphertext)
        tampered = encrypted[:-1] + b'\x00'

        with pytest.raises(Exception, match="Failed to decrypt OTP"):
            authenticator.decrypt_otp(tampered, pin="1234")

    def test_user_not_found(self, verifier):
        with pytest.raises(Exception, match="User not found"):
            verifier.encrypt_otp_for_user("ghost", "123")
