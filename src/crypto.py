from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import os

class CryptoUtils:
    @staticmethod
    def generate_key_pair():
        """Generates an ECC private key."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        return private_key

    @staticmethod
    def get_public_key(private_key):
        """Extracts the public key from the private key."""
        return private_key.public_key()

    @staticmethod
    def sign_data(private_key, data: bytes) -> bytes:
        """Signs the data using the private key."""
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    @staticmethod
    def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
        """Verifies the signature using the public key."""
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def serialize_public_key(public_key) -> bytes:
        """Serializes the public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_public_key(pem_data: bytes):
        """Loads a public key from PEM format."""
        return serialization.load_pem_public_key(pem_data)
