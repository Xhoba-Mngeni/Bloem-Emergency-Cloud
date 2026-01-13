from src.crypto_utils import encrypt_value, decrypt_value

def test_encryption_decryption():
    original = "Sensitive Medical Data"
    encrypted = encrypt_value(original)
    
    assert encrypted != original
    assert len(encrypted) > len(original)
    
    decrypted = decrypt_value(encrypted)
    assert decrypted == original

def test_decrypt_unencrypted_data():
    plain_text = "Plain Text Data"
    result = decrypt_value(plain_text)
    assert result == plain_text

def test_empty_values():
    assert encrypt_value("") == ""
    assert decrypt_value("") == ""
    assert encrypt_value(None) is None
    assert decrypt_value(None) is None
