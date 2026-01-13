import hashlib
from datetime import datetime
from .database import get_db_connection, put_db_connection

def log_action(doctor_username: str, patient_sa_id: str, action_type: str, reason: str):
    """
    Logs an action to the audit_logs table with a blockchain-style hash chain.
    This ensures that logs cannot be tampered with without breaking the chain.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # 1. Get the last hash
            cur.execute("SELECT log_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            prev_hash = row[0] if row else "0" * 64

            # 2. Prepare data for hashing
            timestamp = datetime.now()
            
            # Construct payload to hash
            payload = f"{timestamp.isoformat()}|{doctor_username}|{patient_sa_id}|{action_type}|{reason}|{prev_hash}"
            
            # 3. Calculate new hash
            log_hash = hashlib.sha256(payload.encode()).hexdigest()

            # 4. Insert Record
            cur.execute("""
                INSERT INTO audit_logs 
                (access_time, doctor_username, patient_sa_id, action_type, reason, prev_hash, log_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (timestamp, doctor_username, patient_sa_id, action_type, reason, prev_hash, log_hash))
            
            conn.commit()
            return log_hash
    except Exception as e:
        conn.rollback()
        print(f"❌ Audit Log Error: {e}")
        raise e
    finally:
        put_db_connection(conn)

def verify_chain():
    """
    Verifies the integrity of the audit log chain.
    Returns (True, "Valid") or (False, "Tampering detected at ID X")
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, access_time, doctor_username, patient_sa_id, action_type, reason, prev_hash, log_hash FROM audit_logs ORDER BY id ASC")
            logs = cur.fetchall()
            
            if not logs:
                return True, "No logs to verify"

            expected_prev = "0" * 64

            for log in logs:
                log_id, access_time, doctor, patient, action, reason, prev_hash, stored_hash = log
                
                if prev_hash != expected_prev:
                    return False, f"Broken Chain Link at ID {log_id}: Previous hash mismatch"

                    # Recalculate hash
                payload = f"{access_time.isoformat()}|{doctor}|{patient}|{action}|{reason}|{prev_hash}"
                recalc_hash = hashlib.sha256(payload.encode()).hexdigest()

                if recalc_hash != stored_hash:
                     return False, f"Data Tampering at ID {log_id}: Hash mismatch"

                expected_prev = stored_hash
            
            return True, "Chain Integrity Verified"
    finally:
        put_db_connection(conn)
