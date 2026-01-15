from src.crypto import CryptoUtils
import os

class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        # In a real decentralized system, this would be a distributed ledger or DHT.
        # Here we simulate it with an in-memory dictionary.
        self.registry = {}

    def register_user(self, user_id, public_key_pem):
        """Registers a user's public key."""
        if user_id in self.registry:
            # Simplified: In real world, we would check if it's an update or conflict
            return False, "User already exists"

        try:
            # Validate the key format
            CryptoUtils.load_public_key(public_key_pem)
            self.registry[user_id] = public_key_pem
            return True, "User registered successfully"
        except Exception as e:
            return False, str(e)

    def generate_challenge(self):
        """Generates a random challenge (nonce)."""
        return os.urandom(32)

    def verify_auth(self, user_id, challenge, signature):
        """Verifies the authentication response."""
        if user_id not in self.registry:
            return False, "User not found"

        public_key_pem = self.registry[user_id]
        public_key = CryptoUtils.load_public_key(public_key_pem)

        is_valid = CryptoUtils.verify_signature(public_key, signature, challenge)
        if is_valid:
            return True, "Authentication successful"
        else:
            return False, "Invalid signature"

    def sync_registry(self, other_registry):
        """Simulates P2P syncing of the registry."""
        self.registry.update(other_registry)
