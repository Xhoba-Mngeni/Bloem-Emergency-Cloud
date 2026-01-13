from dotenv import load_dotenv
from database import get_db_connection, put_db_connection

load_dotenv()

def run_compliance_check():
    print("⚖️ STARTING COMPLIANCE AUDIT...")
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # 1. Identify records > 5 years old for the retention policy
        cur.execute("SELECT sa_id_number, created_at FROM patients WHERE created_at < NOW() - INTERVAL '5 years'")
        old_records = cur.fetchall()
        
        if old_records:
            print(f"⚠️ FOUND {len(old_records)} RECORDS EXCEEDING RETENTION PERIOD (5 YEARS)")
            for rec in old_records:
                print(f"   - SA ID: {rec[0]} (Created: {rec[1]}) -> FLAGGED FOR ARCHIVAL")
        else:
            print("✅ Data Retention Check Passed: No records > 5 years old.")

        # 2. Identify Inactive Records > 7 years for the deletion policy
        cur.execute("SELECT sa_id_number, created_at FROM patients WHERE is_active = FALSE AND created_at < NOW() - INTERVAL '7 years'")
        dead_records = cur.fetchall()
        
        if dead_records:
            print(f"🚨 FOUND {len(dead_records)} INACTIVE RECORDS EXCEEDING 7 YEARS")
        else:
             print("✅ Deletion Policy Check Passed: No expungable records found.")

    finally:
        put_db_connection(conn)
    print("⚖️ COMPLIANCE AUDIT COMPLETE.")

if __name__ == "__main__":
    run_compliance_check()
