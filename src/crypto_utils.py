from cryptography.fernet import Fernet
import os
import base64
from dotenv import load_dotenv

load_dotenv()

def get_fernet():
    """
    Derives a valid Fernet key from the hex MASTER_ENCRYPTION_KEY in .env.
    Fernet requires a 32-byte url-safe base64-encoded key.
    """
    hex_key = os.getenv("MASTER_ENCRYPTION_KEY")
    if not hex_key:
        raise ValueError("❌ MASTER_ENCRYPTION_KEY is missing!")
    
    hex_key = hex_key.strip().strip('"').strip("'") 

    try:
        # Convert hex string to bytes
        key_bytes = bytes.fromhex(hex_key)
        # make sure its 32 bytes
        if len(key_bytes) != 32:
             raise ValueError(f"Key must be 32 bytes (64 hex chars), got {len(key_bytes)}")
        
        # Base64 encode for Fernet
        b64_key = base64.urlsafe_b64encode(key_bytes)
        return Fernet(b64_key)
    except Exception as e:
        raise ValueError(f"❌ Invalid Encryption Key: {e}")

_cipher = get_fernet()

def encrypt_value(value: str) -> str:
    """Encrypts a string value."""
    if not value:
        return value
    return _cipher.encrypt(value.encode()).decode()

def decrypt_value(token: str) -> str:
    """Decrypts a string token."""
    if not token:
        return token
    try:
        return _cipher.decrypt(token.encode()).decode()
    except Exception:
        # If decryption fails (e.g., data wasn't encrypted), return original
        # This allows for kinda migration or mixed data
        return token
