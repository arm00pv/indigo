import pytest
from src.node import Node
from src.client import Client
from src.crypto import CryptoUtils

class TestMFAProtocol:

    @pytest.fixture
    def client(self):
        c = Client("user_test")
        c.setup_account(pin="1234")
        return c

    @pytest.fixture
    def node(self):
        return Node(node_id=1)

    def test_crypto_utils(self):
        key = CryptoUtils.generate_key_pair()
        data = b"test message"
        signature = CryptoUtils.sign_data(key, data)
        pub_key = CryptoUtils.get_public_key(key)

        assert CryptoUtils.verify_signature(pub_key, signature, data)
        assert not CryptoUtils.verify_signature(pub_key, signature, b"wrong data")

    def test_registration(self, node, client):
        pub_pem = client.get_public_key_pem()
        success, msg = node.register_user(client.user_id, pub_pem)
        assert success
        assert client.user_id in node.registry

    def test_successful_auth(self, node, client):
        # Register
        node.register_user(client.user_id, client.get_public_key_pem())

        # Challenge
        challenge = node.generate_challenge()

        # Sign with correct PIN
        signature = client.sign_challenge(challenge, pin="1234")

        # Verify
        success, msg = node.verify_auth(client.user_id, challenge, signature)
        assert success
        assert msg == "Authentication successful"

    def test_wrong_pin(self, client):
        with pytest.raises(Exception, match="Invalid PIN"):
            client.sign_challenge(b"challenge", pin="0000")

    def test_invalid_signature_attack(self, node, client):
        # Register
        node.register_user(client.user_id, client.get_public_key_pem())

        challenge = node.generate_challenge()
        fake_signature = b"fake"

        success, msg = node.verify_auth(client.user_id, challenge, fake_signature)
        assert not success
        assert msg == "Invalid signature"

    def test_user_not_found(self, node):
        success, msg = node.verify_auth("unknown_user", b"chal", b"sig")
        assert not success
        assert msg == "User not found"
