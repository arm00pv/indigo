from src.crypto import CryptoUtils

class Client:
    def __init__(self, user_id):
        self.user_id = user_id
        self._private_key = None
        self._pin = None

    def setup_account(self, pin):
        """Generates keys and sets a PIN."""
        self._private_key = CryptoUtils.generate_key_pair()
        self._pin = pin

    def get_public_key_pem(self):
        """Returns the public key in PEM format for registration."""
        if not self._private_key:
            raise Exception("Account not setup")

        public_key = CryptoUtils.get_public_key(self._private_key)
        return CryptoUtils.serialize_public_key(public_key)

    def sign_challenge(self, challenge, pin):
        """Signs the challenge if the PIN matches."""
        if not self._private_key:
            raise Exception("Account not setup")

        if pin != self._pin:
            raise Exception("Invalid PIN")

        return CryptoUtils.sign_data(self._private_key, challenge)
