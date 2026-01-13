from fastapi.testclient import TestClient
from src.main import app
from src.database import get_db_connection, put_db_connection
from src import audit_logger
import pyotp

client = TestClient(app, base_url="http://localhost")

def setup_module(module):
    """Ensure clean state before tests"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE audit_logs RESTART IDENTITY CASCADE")
            conn.commit()
    finally:
        put_db_connection(conn)

def test_tamper_proof_logs():
    print("\n🧪 Testing Audit Log Immutability...")
    
    # 1 Log legitimate actions
    audit_logger.log_action("dr_test", "123456", "VIEW", "Test 1")
    audit_logger.log_action("dr_test", "123456", "VIEW", "Test 2")
    
    # 2 Verify Chain
    is_valid, msg = audit_logger.verify_chain()
    assert is_valid, f"Chain should be valid: {msg}"
    print("✅ Chain Validated Successfully")
    
    # 3 Tamper with a record
    print("😈 Attempting to tamper with logs...")
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # this tampers with the first record. This should invalidate the hash of the secondrecord.
            cur.execute("UPDATE audit_logs SET reason = 'HACKED' WHERE reason = 'Test 1'")
            conn.commit()
    finally:
        put_db_connection(conn)
        
    # 4  Verify Failure
    is_valid, msg = audit_logger.verify_chain()
    assert not is_valid, "Chain should be invalid after tampering"
    print(f"✅ Tampering Detected: {msg}")

def test_mfa_flow():
    print("\n🔐 Testing MFA Flow...")
    
    # Makes sure user starts without MFA enabled
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET mfa_secret = NULL WHERE username = %s", ("dr_xhoba",))
            conn.commit()
    finally:
        put_db_connection(conn)
    
    # 1 Login 
    res = client.post("/token", data={"username": "dr_xhoba", "password": "medical123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("✅ Initial Login Success")
    
    # 2 Setup MFA
    res = client.post("/auth/mfa/setup", headers=headers)
    assert res.status_code == 200
    data = res.json()
    secret = data["secret"]
    assert "qr_code" in data
    print("✅ MFA Setup Initiated (Secret Generated)")
    
    # 3 Verify & Enable MFA
    totp = pyotp.TOTP(secret)
    code = totp.now()
    
    res = client.post("/auth/mfa/verify", data={"code": code, "secret": secret}, headers=headers)
    assert res.status_code == 200
    print("✅ MFA Verified & Enabled")
    
    # 4. Login Again (Should require MFA)
    res = client.post("/token", data={"username": "dr_xhoba", "password": "medical123"})
    assert res.status_code == 403
    assert res.json()["detail"] == "MFA_REQUIRED"
    print("✅ Login correctly rejected without MFA Code")
    
    # Second attempt with code
    code = totp.now()
    res = client.post("/token", data={"username": "dr_xhoba", "password": "medical123", "mfa_code": code})
    if res.status_code != 200:
        print(f"❌ Login Failed: {res.text}")
    assert res.status_code == 200
    assert bool(res.json()["mfa_enabled"])
    print("✅ Login Success with MFA Code")
