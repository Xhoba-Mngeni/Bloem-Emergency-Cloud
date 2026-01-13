from fastapi.testclient import TestClient
from src.main import app
from src.auth import create_access_token, create_refresh_token, hash_refresh_token
from src.main import ensure_refresh_table
from src.database import get_db_connection, put_db_connection

client = TestClient(app, base_url="http://localhost")

def login_and_get_tokens(username="dr_xhoba"):
    # Ensure user has no MFA for this test
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET mfa_secret = NULL WHERE username = %s", (username,))
            conn.commit()
    finally:
        put_db_connection(conn)
    data = {
        "username": username,
        "password": "medical123"
    }
    r = client.post("/token", data=data)
    assert r.status_code == 200
    j = r.json()
    return j["access_token"], j.get("refresh_token")

def test_security_headers_present():
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers.get("Strict-Transport-Security") is not None
    assert r.headers.get("Content-Security-Policy") is not None
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("Referrer-Policy") == "no-referrer"

def test_rate_limit_patient_search():
    access_token, _ = login_and_get_tokens()
    headers = {"Authorization": f"Bearer {access_token}", "User-Agent": "testclient"}
    last_status = None
    for i in range(21):
        r = client.get("/patient/search", params={"sa_id": "1200000000000"}, headers=headers)
        last_status = r.status_code
        if last_status == 429:
            break
    assert last_status == 429

def test_refresh_and_logout_flow():
    access_token, refresh_token = login_and_get_tokens()
    assert refresh_token is not None
    r = client.post("/auth/refresh", data={"refresh_token": refresh_token}, headers={"User-Agent": "testclient"})
    assert r.status_code == 200
    new_tokens = r.json()
    assert "access_token" in new_tokens and "refresh_token" in new_tokens
    r2 = client.post("/auth/logout", data={"refresh_token": refresh_token})
    assert r2.status_code == 200
    r3 = client.post("/auth/refresh", data={"refresh_token": refresh_token})
    assert r3.status_code == 401

def test_rate_limit_emergency_summary():
    token = create_access_token({"sub": "dr_strange", "role": "doctor"})
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "testclient"}
    status = None
    for i in range(6):
        r = client.post("/emergency-summary", json={"sa_id": "0000000000000", "reason": "Test"}, headers=headers)
        status = r.status_code
        if status == 429:
            break
    assert status == 429

def test_refresh_device_binding():
    conn = get_db_connection()
    try:
        ensure_refresh_table(conn)
        with conn.cursor() as cur:
            rt = create_refresh_token({"sub": "dr_xhoba"})
            cur.execute("DELETE FROM refresh_tokens WHERE username = %s", ("dr_xhoba",))
            cur.execute(
                "INSERT INTO refresh_tokens (username, token_hash, expires_at, user_agent, ip) VALUES (%s, %s, CURRENT_TIMESTAMP + INTERVAL '7 days', %s, %s)",
                ("dr_xhoba", hash_refresh_token(rt), "testclient", "127.0.0.1")
            )
            conn.commit()
    finally:
        put_db_connection(conn)
    bad = client.post("/auth/refresh", data={"refresh_token": rt}, headers={"User-Agent": "other-UA"})
    assert bad.status_code == 401
    ok = client.post("/auth/refresh", data={"refresh_token": rt}, headers={"User-Agent": "testclient", "X-Forwarded-For": "127.0.0.1"})
    assert ok.status_code == 200

def test_account_lockout_on_failed_logins():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM audit_logs WHERE doctor_username = %s AND action_type = 'LOGIN_FAILED'", ("dr_strange",))
            conn.commit()
    finally:
        put_db_connection(conn)
    # Pre seed 5 failed attempts in the last minute to trigger lockout
    from src import audit_logger
    for i in range(5):
        audit_logger.log_action("dr_strange", "SYSTEM", "LOGIN_FAILED", "Test Failure")
    r = client.post("/token", data={"username": "dr_strange", "password": "wrong"})
    assert r.status_code == 429

def test_admin_unlock_user():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM audit_logs WHERE doctor_username = %s AND action_type = 'LOGIN_FAILED'", ("dr_strange",))
            conn.commit()
    finally:
        put_db_connection(conn)
    from src import audit_logger
    for i in range(5):
        audit_logger.log_action("dr_strange", "SYSTEM", "LOGIN_FAILED", "Seed Fail")
    from src.auth import create_access_token
    admin_token = create_access_token({"sub": "dr_xhoba", "role": "admin"})
    headers = {"Authorization": f"Bearer {admin_token}"}
    u = client.post("/admin/unlock-user", data={"target_username": "dr_strange"}, headers=headers)
    assert u.status_code == 200
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) FROM audit_logs 
                WHERE doctor_username = %s AND action_type = 'LOGIN_FAILED' 
                  AND access_time > (CURRENT_TIMESTAMP - INTERVAL '15 minutes')
            """, ("dr_strange",))
            cnt = cur.fetchone()[0]
            assert cnt == 0
    finally:
        put_db_connection(conn)
