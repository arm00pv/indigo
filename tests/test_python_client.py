import pytest
import os
import hashlib
import json
import struct
from mfa_sdk.authenticator import Authenticator
from mfa_sdk.crypto import CryptoUtils
from mfa_sdk.verifier import Verifier, VerificationStatus

def test_authenticator_standard_flow():
    """Verify standard Auth flow with updated Crypto."""
    user_id = "test_user"
    auth = Authenticator(user_id)

    # Setup Client
    pin = "1234"
    auth.setup_account(pin)

    # Register (Server Side)
    pub_pem = auth.get_public_key_pem()
    verifier = Verifier("test_verifier")
    verifier.register_user(user_id, pub_pem)

    # Generate & Encrypt Challenge (Server Side)
    otp = "123456"
    encrypted_blob = verifier.encrypt_otp_for_user(user_id, otp)

    # Verify Blob Format (New X9.62)
    # 65 bytes (Key) + 12 bytes (Nonce) + Ciphertext
    assert len(encrypted_blob) >= 65 + 12
    # Ensure no length prefix (if it was length prefixed, first byte would likely be 0 for length < 255)
    # First byte of uncompressed point is 0x04
    assert encrypted_blob[0] == 0x04

    # Decrypt (Client Side) - Legacy Mode (Plain PIN)
    decrypted_otp, context = auth.decrypt_otp(encrypted_blob, pin)
    assert decrypted_otp == otp
    assert context is None

def test_authenticator_duress_flow():
    """Verify Duress flow with updated Crypto."""
    user_id = "test_user_duress"
    auth = Authenticator(user_id)

    pin = "1111"
    duress = "9999"
    auth.setup_account(pin, duress)

    verifier = Verifier("test_verifier")
    verifier.register_user(user_id, auth.get_public_key_pem())

    otp = "123456"
    encrypted_blob = verifier.encrypt_otp_for_user(user_id, otp)

    # Decrypt with Duress PIN
    decrypted_otp, _ = auth.decrypt_otp(encrypted_blob, duress)

    # Should be modified
    assert decrypted_otp != otp
    assert decrypted_otp == "123457"

    # Server Verify
    status = verifier.verify_otp(otp, decrypted_otp)
    assert status == VerificationStatus.DURESS

def test_authenticator_context_aware():
    """Verify Context-Aware Auth."""
    user_id = "context_user"
    auth = Authenticator(user_id)
    auth.setup_account("1234")

    verifier = Verifier("verifier")
    verifier.register_user(user_id, auth.get_public_key_pem())

    otp = "555555"
    ctx = "Transfer $1000"
    encrypted_blob = verifier.encrypt_otp_for_user(user_id, otp, context=ctx)

    decrypted_otp, context = auth.decrypt_otp(encrypted_blob, "1234")
    assert decrypted_otp == otp
    assert context == ctx

def test_legacy_authenticator_compatibility():
    """
    Ensure the Client SDK handles the new format correctly.
    Since we updated mfa_sdk.crypto.CryptoUtils.decrypt_data,
    the Authenticator (which uses it) should work automatically.
    """
    # This is covered by test_authenticator_standard_flow
    pass
