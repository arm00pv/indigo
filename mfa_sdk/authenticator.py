from mfa_sdk.crypto import CryptoUtils
from mfa_sdk.common import get_duress_otp

class Authenticator:
    def __init__(self, user_id):
        self.user_id = user_id
        self._private_key = None
        self._pin = None
        self._duress_pin = None

    def setup_account(self, pin, duress_pin=None):
        """Generates keys and sets a PIN. Simulates secure storage."""
        self._private_key = CryptoUtils.generate_key_pair()
        self._pin = pin
        self._duress_pin = duress_pin

    def get_public_key_pem(self):
        """Returns the public key in PEM format for registration."""
        if not self._private_key:
            raise Exception("Account not setup")

        public_key = CryptoUtils.get_public_key(self._private_key)
        return CryptoUtils.serialize_public_key(public_key)

    def decrypt_otp(self, encrypted_otp_blob, pin):
        """
        Decrypts the OTP sent by the verifier.
        Requires the correct PIN or Duress PIN to access the private key.
        If Duress PIN is used, the OTP is stealthily modified.
        """
        if not self._private_key:
            raise Exception("Account not setup")

        is_duress = False
        if pin == self._pin:
            is_duress = False
        elif self._duress_pin and pin == self._duress_pin:
            is_duress = True
        else:
            raise Exception("Invalid PIN")

        try:
            plaintext = CryptoUtils.decrypt_data(self._private_key, encrypted_otp_blob)
            otp = plaintext.decode('utf-8')

            if is_duress:
                return get_duress_otp(otp)
            return otp

        except Exception as e:
            raise Exception("Failed to decrypt OTP. Key mismatch or corrupted data.")
