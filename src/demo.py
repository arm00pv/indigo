from src.node import Node
from src.client import Client
import time

def simulate_decentralized_auth():
    print("=== Decentralized MFA Protocol Demo ===\n")

    # 1. Setup the Network (Simulating 3 decentralized nodes)
    print("[Network] Initializing decentralized nodes...")
    nodes = [Node(node_id=i) for i in range(3)]

    # 2. User Setup
    user_id = "alice@example.com"
    print(f"[Client] User '{user_id}' is setting up their device...")
    client = Client(user_id)
    client.setup_account(pin="1234")

    # 3. Registration
    print("[Client] Generating keys and registering with the network...")
    public_key_pem = client.get_public_key_pem()

    # In a real scenario, this would broadcast to the network.
    # We simulate propagation.
    for node in nodes:
        success, msg = node.register_user(user_id, public_key_pem)
        print(f"  -> Node {node.node_id}: {msg}")

    print("\n[Network] Registration complete. Public key stored on distributed nodes.\n")

    # 4. Authentication Attempt
    print("[Auth] Starting authentication process...")

    # Step 4a: Client requests auth from a random node (or all)
    verifier_node = nodes[0] # Pick one node to challenge
    print(f"[Network] Node {verifier_node.node_id} received auth request.")

    # Step 4b: Node generates challenge
    challenge = verifier_node.generate_challenge()
    print(f"[Network] Challenge sent: {challenge.hex()[:10]}...")

    # Step 4c: Client signs challenge (User interaction)
    try:
        # User enters PIN
        user_pin = "1234"
        print(f"[Client] User enters PIN: {user_pin}")
        signature = client.sign_challenge(challenge, user_pin)
        print("[Client] Challenge signed.")
    except Exception as e:
        print(f"[Client] Error signing challenge: {e}")
        return

    # Step 4d: Node verifies signature
    print(f"[Network] Node {verifier_node.node_id} verifying signature...")
    success, message = verifier_node.verify_auth(user_id, challenge, signature)

    if success:
        print(f"✅ SUCCESS: {message}")
    else:
        print(f"❌ FAILED: {message}")

    # 5. Attack Simulation (Replay Attack / Invalid Signature)
    print("\n[Attack Simulation] Trying to use an invalid signature...")
    fake_signature = b'\x00' * 64
    success, message = verifier_node.verify_auth(user_id, challenge, fake_signature)
    if not success:
         print(f"✅ BLOCKED: {message} (As expected)")

if __name__ == "__main__":
    simulate_decentralized_auth()
