from .auth import authenticate_user, create_access_token, require_admin, RoleChecker, generate_mfa_secret, get_mfa_uri, verify_mfa_code, generate_qr_base64, create_refresh_token, hash_refresh_token, ALGORITHM
from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from . import audit_logger
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from datetime import timedelta
from datetime import datetime, timezone
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded


from .models import PatientCreate
from .database import get_db_connection, put_db_connection
from .ai_engine import analyze_patient_safety
from .crypto_utils import encrypt_value, decrypt_value

# Security config
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 1. Security Headers (Helmet-like protection)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# 2. Trusted Host (Prevent Host Header Attacks)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "::1"])

# Mount Frontend
app.mount("/static", StaticFiles(directory="src/static"), name="static")

# 3. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"], # Frontend dev server
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def ensure_refresh_table(conn):
    try:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) REFERENCES users(username),
                token_hash VARCHAR(64) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                revoked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            cur.execute("ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS user_agent VARCHAR(200)")
            cur.execute("ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS ip VARCHAR(45)")
            conn.commit()
    except Exception:
        conn.rollback()

# AUTH endpointa
@app.post("/token")
@limiter.limit("5/minute")  # security rate limits 
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), mfa_code: Optional[str] = Form(None)):
    # The account lockout check after 5 failed attempts in 15 minutes
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) FROM audit_logs 
                WHERE doctor_username = %s AND action_type = 'LOGIN_FAILED' 
                  AND access_time > (CURRENT_TIMESTAMP - INTERVAL '15 minutes')
            """, (form_data.username,))
            failed_count = cur.fetchone()[0]
            if failed_count >= 5:
                try:
                    audit_logger.log_action(form_data.username, "SYSTEM", "LOGIN_LOCKED", "Lockout threshold exceeded")
                except Exception:
                    pass
                raise HTTPException(status_code=429, detail="ACCOUNT_LOCKED")
    finally:
        put_db_connection(conn)
    
    user = authenticate_user(form_data.username, form_data.password)
    
    # This one tracks the track login attempts
    action = "LOGIN_SUCCESS" if user else "LOGIN_FAILED"
    try:
        audit_logger.log_action(form_data.username, "SYSTEM", action, "Login Attempt")
    except Exception as e:
        print(f"Audit Log Failed: {e}")

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    # MFA check
    if user.get("mfa_secret"):
        if not mfa_code:
            raise HTTPException(status_code=403, detail="MFA_REQUIRED")
        
        if not verify_mfa_code(user["mfa_secret"], mfa_code):
             raise HTTPException(status_code=403, detail="Invalid MFA Code")

    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]}, expires_delta=timedelta(minutes=30))
    refresh_token = create_refresh_token(data={"sub": user["username"]}, expires_delta=timedelta(days=7))
    # Store hashed refresh token
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            ensure_refresh_table(conn)
            cur.execute("DELETE FROM refresh_tokens WHERE username = %s OR (expires_at < CURRENT_TIMESTAMP)", (user["username"],))
            cur.execute(
                "INSERT INTO refresh_tokens (username, token_hash, expires_at, user_agent, ip) VALUES (%s, %s, %s, %s, %s)",
                (
                    user["username"],
                    hash_refresh_token(refresh_token),
                    datetime.now(timezone.utc) + timedelta(days=7),
                    request.headers.get("User-Agent", ""),
                    (request.headers.get("X-Forwarded-For", "").split(",")[0].strip() if request.headers.get("X-Forwarded-For") else (request.client.host if request.client else ""))
                )
            )
            conn.commit()
    finally:
        put_db_connection(conn)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer", "mfa_enabled": bool(user.get("mfa_secret"))}

@app.post("/auth/refresh")
def refresh_access_token(refresh_token: str = Form(...), request: Request = None):
    from jose import jwt
    from .auth import REFRESH_SECRET_KEY
    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            ensure_refresh_table(conn)
            cur.execute(
                "SELECT id, token_hash, expires_at, revoked, user_agent, ip FROM refresh_tokens WHERE token_hash = %s ORDER BY created_at DESC LIMIT 1",
                (hash_refresh_token(refresh_token),)
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="Refresh token not found")
            _id, token_hash, expires_at, revoked, stored_ua, stored_ip = row
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if revoked or expires_at < datetime.now(timezone.utc):
                raise HTTPException(status_code=401, detail="Refresh token expired or revoked")
            if token_hash != hash_refresh_token(refresh_token):
                raise HTTPException(status_code=401, detail="Refresh token mismatch")
            curr_ua = request.headers.get("User-Agent", "") if request else ""
            xff = request.headers.get("X-Forwarded-For", "") if request else ""
            curr_ip = xff.split(",")[0].strip() if xff else (request.client.host if (request and request.client) else "")
            if stored_ua and curr_ua and stored_ua != curr_ua:
                raise HTTPException(status_code=401, detail="Device mismatch (UA)")
            if stored_ip and curr_ip and stored_ip != curr_ip:
                raise HTTPException(status_code=401, detail="Device mismatch (IP)")
            # Rotate: delete old and issue a new one
            cur.execute("SELECT role FROM users WHERE username = %s", (username,))
            role_row = cur.fetchone()
            role = role_row[0] if role_row else "doctor"
            new_access = create_access_token({"sub": username, "role": role}, expires_delta=timedelta(minutes=30))
            new_refresh = create_refresh_token({"sub": username}, expires_delta=timedelta(days=7))
            cur.execute("DELETE FROM refresh_tokens WHERE id = %s", (_id,))
            cur.execute(
                "INSERT INTO refresh_tokens (username, token_hash, expires_at, user_agent, ip) VALUES (%s, %s, %s, %s, %s)",
                (username, hash_refresh_token(new_refresh), datetime.now(timezone.utc) + timedelta(days=7), curr_ua, curr_ip)
            )
            conn.commit()
            return {"access_token": new_access, "refresh_token": new_refresh}
    finally:
        put_db_connection(conn)

@app.post("/auth/logout")
def logout_user(refresh_token: str = Form(...)):
    # Revoke refresh token
    from jose import jwt
    from .auth import REFRESH_SECRET_KEY
    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    username = payload.get("sub")
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            ensure_refresh_table(conn)
            cur.execute("UPDATE refresh_tokens SET revoked = TRUE WHERE username = %s AND token_hash = %s", (username, hash_refresh_token(refresh_token)))
            conn.commit()
    finally:
        put_db_connection(conn)
    try:
        audit_logger.log_action(username, "SYSTEM", "LOGOUT", "User Logout")
    except Exception:
        pass
    return {"message": "Logged out"}

@app.post("/auth/mfa/setup")
def setup_mfa(user: dict = Depends(RoleChecker(["admin", "doctor", "nurse", "paramedic"]))):
    """
    Generates a new MFA secret and QR code for the user.
    Note: This does NOT enable it yet. User must verify to enable.
    """
    secret = generate_mfa_secret()
    uri = get_mfa_uri(secret, user["username"])
    qr_b64 = generate_qr_base64(uri)
    
    return {
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_b64}",
        "message": "Scan this QR code with Google Authenticator, then call /auth/mfa/verify to enable."
    }

@app.post("/auth/mfa/verify")
def verify_and_enable_mfa(code: str = Form(...), secret: str = Form(...), user: dict = Depends(RoleChecker(["admin", "doctor", "nurse", "paramedic"]))):
    """
    Verifies the code against the provided secret. If valid, saves secret to DB.
    """
    if verify_mfa_code(secret, code):
        # SAVE TO DB
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET mfa_secret = %s WHERE username = %s", (secret, user["username"]))
                conn.commit()
        finally:
            put_db_connection(conn)
        
        audit_logger.log_action(user["username"], "SYSTEM", "MFA_ENABLED", "User enabled 2FA")
        return {"message": "MFA Enabled Successfully! Next login will require code."}
    else:
        raise HTTPException(status_code=400, detail="Invalid Code")

@app.get("/")
async def root():
    from fastapi.responses import FileResponse
    return FileResponse('src/static/index.html')

# This is the patients endpoints
@app.get("/patient/search")
@limiter.limit("20/minute") # this security prevents Mass Scraping
def search_patient(request: Request, sa_id: str, user: dict = Depends(RoleChecker(["admin", "doctor", "nurse", "paramedic"]))):
    conn = get_db_connection()
    try:
        cur = conn.cursor()

        # 1. fetch the basic info
        cur.execute("""
            SELECT sa_id_number, first_name, last_name, blood_type, emergency_contact,
                   previous_surgeries, allergies, is_active, consent_status,
                   emergency_contact_name, emergency_contact_surname, emergency_contact_relationship
            FROM patients WHERE sa_id_number = %s
        """, (sa_id,))
        row = cur.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Patient not found")

        patient_data = {
            "sa_id": row[0],
            "first_name": decrypt_value(row[1]),
            "last_name": decrypt_value(row[2]),
            "blood_type": row[3],
            "emergency_contact": row[4],
            "emergency_contact_name": (decrypt_value(row[9]) if len(row) > 9 and row[9] else None),
            "emergency_contact_surname": (decrypt_value(row[10]) if len(row) > 10 and row[10] else None),
            "emergency_contact_relationship": (decrypt_value(row[11]) if len(row) > 11 and row[11] else None),
            "previous_surgeries": row[5],
            "allergies": decrypt_value(row[6]),
            "is_active": row[7],
            "consent_status": row[8]
        }

        if not patient_data['is_active']:
            raise HTTPException(status_code=404, detail="Record Archived")

        # 2 Check Consent Withheld first
        if patient_data['consent_status'] == 'WITHHELD':
            # This part logs the denied access
            audit_logger.log_action(user['username'], sa_id, 'DENIED', 'Consent Withheld')
            raise HTTPException(status_code=403, detail="⚠️ Consent Withheld. Use Break-Glass Protocol.")
        
        # 3 Check Restricted Access
        if sa_id.endswith('9'):
            raise HTTPException(status_code=403, detail="Restricted Record")

        # 3 Fetch History & Meds
        cur.execute("SELECT condition_name, diagnosis_date FROM medical_history WHERE patient_id = %s", (sa_id,))
        history = [{"name": decrypt_value(r[0]), "date": str(r[1])} for r in cur.fetchall()]

        cur.execute("SELECT med_name, dosage FROM medications WHERE patient_id = %s", (sa_id,))
        meds = [{"name": r[0], "dosage": r[1]} for r in cur.fetchall()]
        
        # 4 Audit Log 
        audit_logger.log_action(user['username'], sa_id, 'VIEW', 'Standard Search')
        # 5. Run AI Check
        safety_report = analyze_patient_safety(history, meds, patient_data['allergies'])

        return {
            "patient": patient_data,
            "medical_history": history,
            "current_medications": meds,
            "ai_safety_analysis": safety_report
        }
    finally:
        put_db_connection(conn)

@app.post("/patient/add")
@limiter.limit("10/minute")
def create_patient(request: Request, patient: PatientCreate, user: dict = Depends(RoleChecker(["admin", "doctor"]))):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("ALTER TABLE patients ADD COLUMN IF NOT EXISTS emergency_contact_name TEXT")
        cur.execute("ALTER TABLE patients ADD COLUMN IF NOT EXISTS emergency_contact_surname TEXT")
        cur.execute("ALTER TABLE patients ADD COLUMN IF NOT EXISTS emergency_contact_relationship VARCHAR(30)")
        # Encrypt sensitive fields
        enc_first_name = encrypt_value(patient.first_name)
        enc_last_name = encrypt_value(patient.last_name)
        enc_allergies = encrypt_value(patient.allergies)
        enc_ec_name = encrypt_value(patient.emergency_contact_name) if patient.emergency_contact_name else None
        enc_ec_surname = encrypt_value(patient.emergency_contact_surname) if patient.emergency_contact_surname else None
        enc_ec_relation = encrypt_value(patient.emergency_contact_relationship) if patient.emergency_contact_relationship else None
        
        cur.execute("""
            INSERT INTO patients (sa_id_number, first_name, last_name, blood_type, emergency_contact, previous_surgeries, allergies, consent_status, emergency_contact_name, emergency_contact_surname, emergency_contact_relationship)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING sa_id_number;
        """, (
            patient.sa_id, enc_first_name, enc_last_name, 
            patient.blood_type, patient.emergency_contact, 
            patient.previous_surgeries, enc_allergies,
            patient.consent_status,
            enc_ec_name, enc_ec_surname, enc_ec_relation
        ))
        
        if patient.condition:
            enc_condition = encrypt_value(patient.condition)
            cur.execute("INSERT INTO medical_history (patient_id, condition_name) VALUES (%s, %s)", (patient.sa_id, enc_condition))
            
        if patient.medication:
            cur.execute("INSERT INTO medications (patient_id, med_name, dosage) VALUES (%s, %s, 'Standard')", (patient.sa_id, patient.medication))

        conn.commit()
        return {"msg": "Patient created successfully"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        put_db_connection(conn)

# The admin stats 
@app.get("/admin/stats")
def get_dashboard_stats(user: dict = Depends(require_admin)):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM patients WHERE is_active = TRUE")
        total_patients = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM audit_logs WHERE access_time::date = CURRENT_DATE")
        todays_activity = cur.fetchone()[0]
        return {"total_patients": total_patients, "todays_activity": todays_activity, "system_status": "🟢 ONLINE"}
    except Exception:
        return {"total_patients": 0, "todays_activity": 0, "system_status": "🔴 ERROR"}
    finally:
        put_db_connection(conn)

# the logs
@app.get("/admin/logs")
def get_logs(user: dict = Depends(require_admin)):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT access_time, doctor_username, patient_sa_id, reason FROM audit_logs ORDER BY access_time DESC LIMIT 50")
        logs = [{"time": str(r[0]), "doctor": r[1], "patient_sa_id": r[2], "reason": r[3]} for r in cur.fetchall()]
        return logs
    finally:
        put_db_connection(conn)

@app.get("/admin/audit/verify")
def audit_verify(user: dict = Depends(require_admin)):
    valid, msg = audit_logger.verify_chain()
    return {"valid": valid, "message": msg}

@app.post("/admin/unlock-user")
def admin_unlock_user(target_username: str = Form(...), user: dict = Depends(require_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM audit_logs 
                WHERE doctor_username = %s 
                  AND action_type = 'LOGIN_FAILED'
                  AND access_time > (CURRENT_TIMESTAMP - INTERVAL '15 minutes')
            """, (target_username,))
            conn.commit()
    finally:
        put_db_connection(conn)
    try:
        audit_logger.log_action(user['username'], target_username, 'ADMIN_UNLOCK', 'Manual unlock by admin')
    except Exception:
        pass
    return {"message": "User unlocked"}

# emergency overide 
@app.post("/emergency-summary")
@limiter.limit("5/minute")
def get_emergency_summary(request: Request, payload: dict, user: dict = Depends(RoleChecker(["admin", "doctor", "nurse", "paramedic"]))):
    sa_id = payload.get("sa_id")
    reason = payload.get("reason")
    
    audit_logger.log_action(user['username'], sa_id, 'BREAK_GLASS', f"Emergency: {reason}")
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT sa_id_number, first_name, last_name, blood_type, emergency_contact,
                   previous_surgeries, allergies, consent_status,
                   emergency_contact_name, emergency_contact_surname, emergency_contact_relationship
            FROM patients WHERE sa_id_number = %s
        """, (sa_id,))
        row = cur.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Patient not found")

        # Decrypt the logic
        patient_data = {
            "sa_id": row[0],
            "first_name": decrypt_value(row[1]),
            "last_name": decrypt_value(row[2]),
            "blood_type": row[3],
            "emergency_contact": row[4],
            "emergency_contact_name": row[8],
            "emergency_contact_surname": row[9],
            "emergency_contact_relationship": row[10],
            "previous_surgeries": row[5],
            "allergies": decrypt_value(row[6]),
            "consent_status": row[7]
        }

        # Fetch meds/history...
        cur.execute("SELECT condition_name, diagnosis_date FROM medical_history WHERE patient_id = %s", (sa_id,))
        history = [{"name": decrypt_value(r[0]), "date": str(r[1])} for r in cur.fetchall()]

        cur.execute("SELECT med_name, dosage FROM medications WHERE patient_id = %s", (sa_id,))
        meds = [{"name": r[0], "dosage": r[1]} for r in cur.fetchall()] 

        return {
            "patient": patient_data,
            "medical_history": history,
            "current_medications": meds,
            "ai_safety_analysis": analyze_patient_safety(history, meds, patient_data['allergies'])
        }

    finally:
        put_db_connection(conn)
