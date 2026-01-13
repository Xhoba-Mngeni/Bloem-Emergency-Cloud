from dotenv import load_dotenv
from passlib.context import CryptContext
import random
from database import get_db_connection, put_db_connection
from crypto_utils import encrypt_value

load_dotenv()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_tables(cur):
    print("⏳ Creating tables...")
    
    # 1 USERS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(50) PRIMARY KEY,
        password_hash VARCHAR(200) NOT NULL,
        role VARCHAR(20) DEFAULT 'doctor',
        mfa_secret VARCHAR(32) -- For TOTP (Google Authenticator)
    );
    """)

    # 2 PATIENTS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS patients (
        sa_id_number VARCHAR(13) PRIMARY KEY,
        first_name TEXT,
        last_name TEXT,
        blood_type VARCHAR(5),
        emergency_contact VARCHAR(20),
        previous_surgeries TEXT,
        allergies TEXT DEFAULT 'None Known',
        is_active BOOLEAN DEFAULT TRUE,
        consent_status VARCHAR(20) DEFAULT 'GRANTED',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. MEDICAL HISTORY
    cur.execute("""
    CREATE TABLE IF NOT EXISTS medical_history (
        id SERIAL PRIMARY KEY,
        patient_id VARCHAR(13) REFERENCES patients(sa_id_number),
        condition_name TEXT,
        diagnosis_date DATE DEFAULT CURRENT_DATE
    );
    """)

    # 4. MEDICATIONS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS medications (
        id SERIAL PRIMARY KEY,
        patient_id VARCHAR(13) REFERENCES patients(sa_id_number),
        med_name TEXT,
        dosage VARCHAR(50),
        start_date DATE DEFAULT CURRENT_DATE
    );
    """)

    # 5. AUDIT LOGS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        doctor_username VARCHAR(50),
        patient_sa_id VARCHAR(13),
        action_type VARCHAR(20),
        reason TEXT,
        prev_hash VARCHAR(64), -- Blockchain-style linking
        log_hash VARCHAR(64)   -- Hash of this record + prev_hash
    );
    """)

    # 6. REFRESH TOKENS
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

def seed_data(cur):
    print("🌱 Seeding initial data...")
    
    # Admin Doctor
    hashed_pw = pwd_context.hash("medical123")
    cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", 
                ("dr_xhoba", hashed_pw, "admin"))
    
    # Standard Doctor
    cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", 
                ("dr_strange", hashed_pw, "doctor"))

    # Nurse
    cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", 
                ("nurse_joy", hashed_pw, "nurse"))
                
    # Paramedic
    cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", 
                ("para_medic", hashed_pw, "paramedic"))

    # Generate 50 Dummy Patients
    first_names = ["Lethabo", "Thabo", "Sipho", "Bongani", "Nomsa", "Zanele", "Khanyi", "Mandla", "Naledi", "Lerato"]
    last_names = ["Nkosi", "Dlamini", "Ndlovu", "Khumalo", "Mokoena", "Zulu", "Mthembu", "Ngcobo", "Sithole", "Botha"]
    conditions = ["Asthma", "Diabetes Type 2", "Hypertension", "Epilepsy", "None", "HIV Positive"]
    meds = ["Ventolin", "Metformin", "Amlodipine", "Epilim", "None", "ARVs"]
    allergies_list = ["Penicillin", "Peanuts", "Latex", "Sulfa Drugs", "None Known", "None Known", "None Known"]

    for _ in range(50):
        f_name = random.choice(first_names)
        l_name = random.choice(last_names)
        sa_id = f"{random.randint(70, 99)}{random.randint(1,12):02d}{random.randint(1,28):02d}{random.randint(1000,9999)}{random.randint(0,8)}8{random.randint(1,9)}"
        allergy = random.choice(allergies_list)
        
        # Encrypt sensitive fields
        enc_fname = encrypt_value(f_name)
        enc_lname = encrypt_value(l_name)
        enc_allergies = encrypt_value(allergy)
        
        # Random Consent Status
        consent = random.choice(["GRANTED", "GRANTED", "GRANTED", "WITHHELD"])

        cur.execute("""
            INSERT INTO patients (sa_id_number, first_name, last_name, blood_type, emergency_contact, previous_surgeries, allergies, consent_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
        """, (sa_id, enc_fname, enc_lname, random.choice(["A+", "O+", "B+"]), "072-555-0000", "None", enc_allergies, consent))
        
        # Add random history
        cond = random.choice(conditions)
        if cond != "None":
            enc_cond = encrypt_value(cond)
            cur.execute("INSERT INTO medical_history (patient_id, condition_name) VALUES (%s, %s)", (sa_id, enc_cond))
            
        # Add random med
        med = random.choice(meds)
        if med != "None":
            cur.execute("INSERT INTO medications (patient_id, med_name, dosage) VALUES (%s, %s, '10mg Daily')", (sa_id, med))

def main():
    # Connect to the DB
    conn = get_db_connection()
    conn.autocommit = True
    cur = conn.cursor()
    
    print(f"🔌 Connected to: {conn.dsn}")
    
    # Wipe the old data carefully
    print("⚠️ Wiping old data...")
    cur.execute("DROP TABLE IF EXISTS medications, medical_history, audit_logs, patients, users CASCADE")
    
    create_tables(cur)
    seed_data(cur)
    
    put_db_connection(conn)
    print("✅ Azure/Cloud System Setup Complete!")

if __name__ == "__main__":
    main()
