import secrets

def generate_backup_codes(count=5):
    """Generates a list of random backup codes."""
    codes = []
    for _ in range(count):
        # Format: xxxx-xxxx
        code = f"{secrets.token_hex(2)}-{secrets.token_hex(2)}".upper()
        codes.append(code)
    return codes
