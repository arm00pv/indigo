from mfa_sdk.crypto import CryptoUtils

class Authenticator:
    def __init__(self, user_id):
        self.user_id = user_id
        self._private_key = None
        self._pin = None

    def setup_account(self, pin):
        """Generates keys and sets a PIN. Simulates secure storage."""
        self._private_key = CryptoUtils.generate_key_pair()
        self._pin = pin

    def get_public_key_pem(self):
        """Returns the public key in PEM format for registration."""
        if not self._private_key:
            raise Exception("Account not setup")

        public_key = CryptoUtils.get_public_key(self._private_key)
        return CryptoUtils.serialize_public_key(public_key)

    def decrypt_otp(self, encrypted_otp_blob, pin):
        """
        Decrypts the OTP sent by the verifier.
        Requires the correct PIN to access the private key.
        """
        if not self._private_key:
            raise Exception("Account not setup")

        if pin != self._pin:
            raise Exception("Invalid PIN")

        try:
            plaintext = CryptoUtils.decrypt_data(self._private_key, encrypted_otp_blob)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise Exception("Failed to decrypt OTP. Key mismatch or corrupted data.")
