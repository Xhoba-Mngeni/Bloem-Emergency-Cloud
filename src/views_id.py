import psycopg2
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def view_patients():
    try:
        # Connection to Database
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "127.0.0.1"),
            port=os.getenv("DB_PORT", "5433"),
            user="postgres",
            password=os.getenv("DB_PASSWORD"),
            database="emergency_db"
        )
        cur = conn.cursor()
        
        # Fetch Data
        print("\n🔎 FETCHING PATIENT DATABASE...\n")
        print(f"{'SA ID':<15} | {'NAME':<20} | {'ALLERGIES':<30} | {'ACTIVE'}")
        print("-" * 80)
        
        cur.execute("SELECT sa_id_number, first_name, last_name, allergies, is_active FROM patients LIMIT 20")
        rows = cur.fetchall()
        
        for row in rows:
            sa_id = row[0]
            name = f"{row[1]} {row[2]}"
            allergies = row[3] if row[3] else "None Known"
            active = "✅" if row[4] else "❌"
            
            # This highlights allergies in red if they exist
            if allergies != "None Known":
                allergies = f"\033[91m{allergies}\033[0m"
            
            print(f"{sa_id:<15} | {name:<20} | {allergies:<39} | {active}")

        print("\n✅ Done. Showing first 20 records.")
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    view_patients()