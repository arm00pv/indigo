from mfa_sdk.crypto import CryptoUtils
from mfa_sdk.common import get_duress_otp
import json
import hashlib

class Authenticator:
    def __init__(self, user_id):
        self.user_id = user_id
        self._private_key = None
        self._pin = None
        self._duress_pin = None
        self._pin_hash = None
        self._duress_pin_hash = None

    def setup_account(self, pin, duress_pin=None):
        """Generates keys and sets a PIN. Simulates secure storage."""
        self._private_key = CryptoUtils.generate_key_pair()
        self._pin = pin
        self._duress_pin = duress_pin

    def set_hashes(self, pin_hash, duress_pin_hash=None):
        """Sets PIN hashes directly (Secure Mode). Clears plain PINs."""
        self._pin_hash = pin_hash
        self._duress_pin_hash = duress_pin_hash
        self._pin = None
        self._duress_pin = None

    def get_public_key_pem(self):
        """Returns the public key in PEM format for registration."""
        if not self._private_key:
            raise Exception("Account not setup")

        public_key = CryptoUtils.get_public_key(self._private_key)
        return CryptoUtils.serialize_public_key(public_key)

    def decrypt_otp(self, encrypted_otp_blob, pin):
        """
        Decrypts the OTP sent by the verifier.
        Returns tuple (otp_string, context_string_or_none).

        Requires the correct PIN or Duress PIN to access the private key.
        If Duress PIN is used, the OTP is stealthily modified.
        """
        if not self._private_key:
            raise Exception("Account not setup")

        is_duress = False

        # Check Secure Hash
        if self._pin_hash:
            h = hashlib.sha256(pin.encode('utf-8')).hexdigest()
            if h == self._pin_hash:
                is_duress = False
            elif self._duress_pin_hash and h == self._duress_pin_hash:
                is_duress = True
            else:
                raise Exception("Invalid PIN")
        # Legacy Plain Check
        elif self._pin is not None:
            if pin == self._pin:
                is_duress = False
            elif self._duress_pin and pin == self._duress_pin:
                is_duress = True
            else:
                raise Exception("Invalid PIN")
        else:
            raise Exception("PIN not configured")

        try:
            plaintext = CryptoUtils.decrypt_data(self._private_key, encrypted_otp_blob)
            decoded = plaintext.decode('utf-8')

            otp = decoded
            context = None

            # Try to parse as JSON Context-Aware Payload
            try:
                if decoded.strip().startswith('{'):
                    data = json.loads(decoded)
                    otp = data.get('otp', otp)
                    context = data.get('context')
            except:
                pass # Legacy/Plain format

            if is_duress:
                otp = get_duress_otp(otp)

            return otp, context

        except Exception as e:
            raise Exception(f"Failed to decrypt OTP: {e}")
