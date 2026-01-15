from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os

class CryptoUtils:
    @staticmethod
    def generate_key_pair():
        """Generates an ECC private key."""
        return ec.generate_private_key(ec.SECP256R1())

    @staticmethod
    def get_public_key(private_key):
        """Extracts the public key from the private key."""
        return private_key.public_key()

    @staticmethod
    def sign_data(private_key, data: bytes) -> bytes:
        """Signs the data using the private key."""
        return private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )

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

    @staticmethod
    def encrypt_data(recipient_public_key, plaintext: bytes) -> bytes:
        """
        Encrypts data using ECIES (ECDH + HKDF + AES-GCM).
        Returns: ephemeral_public_key_bytes + nonce + ciphertext + tag
        """
        # 1. Generate Ephemeral Key Pair
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()

        # 2. Perform ECDH
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

        # 3. Derive AES Key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'mfa-protocol-encryption',
        ).derive(shared_key)

        # 4. Encrypt with AES-GCM
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # 5. Serialize Ephemeral Public Key (uncompressed 65 bytes usually, or PEM)
        # Using PEM to be safe and consistent with other methods, though less space efficient.
        # Ideally we'd use X9.62 uncompressed point, but PEM is easier to parse with existing utils.
        eph_pub_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # We need to know the length of the PEM to parse it back.
        # For simplicity, we can prefix length. Or just use a fixed size format (DER).
        # Let's use DER for the ephemeral key to make it easier to parse (TLV).
        eph_pub_der = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Format: [4 bytes length of pubkey][pubkey][12 bytes nonce][ciphertext (includes tag)]
        import struct
        return struct.pack('>I', len(eph_pub_der)) + eph_pub_der + nonce + ciphertext

    @staticmethod
    def decrypt_data(private_key, data: bytes) -> bytes:
        """
        Decrypts data using ECIES.
        """
        import struct

        try:
            # 1. Parse structure
            len_pub_key = struct.unpack('>I', data[:4])[0]
            eph_pub_der = data[4 : 4 + len_pub_key]
            nonce = data[4 + len_pub_key : 4 + len_pub_key + 12]
            ciphertext = data[4 + len_pub_key + 12 :]

            ephemeral_public_key = serialization.load_der_public_key(eph_pub_der)

            # 2. Perform ECDH
            shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

            # 3. Derive AES Key (must match encryption)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'mfa-protocol-encryption',
            ).derive(shared_key)

            # 4. Decrypt
            aesgcm = AESGCM(derived_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext

        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
