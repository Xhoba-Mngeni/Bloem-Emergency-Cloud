from fastapi.testclient import TestClient
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.main import app
from src.auth import create_access_token

client = TestClient(app, base_url="http://localhost")

def test_rbac_and_consent():
    print("🧪 Starting RBAC & Compliance Test...")

    # 1 Setup Tokens
    admin_token = create_access_token({"sub": "dr_xhoba", "role": "admin"})
    doctor_token = create_access_token({"sub": "dr_strange", "role": "doctor"})
    nurse_token = create_access_token({"sub": "nurse_joy", "role": "nurse"})
    
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    doctor_headers = {"Authorization": f"Bearer {doctor_token}"}
    nurse_headers = {"Authorization": f"Bearer {nurse_token}"}
    paramedic_token = create_access_token({"sub": "paramedic_sipho", "role": "paramedic"})
    paramedic_headers = {"Authorization": f"Bearer {paramedic_token}"}

    # 2 Create a patient with CONSENT=WITHHELD (Admin doing it)
    import random
    sa_id = f"{random.randint(10,99)}0101500008{random.randint(0,9)}"
    patient_data = {
        "sa_id": sa_id,
        "first_name": "Test",
        "last_name": "Refuser",
        "blood_type": "O+",
        "emergency_contact": "123",
        "previous_surgeries": "None",
        "allergies": "None",
        "consent_status": "WITHHELD"
    }
    
    print(f"   Creating patient {sa_id} with WITHHELD consent...")
    res = client.post("/patient/add", json=patient_data, headers=admin_headers)
    assert res.status_code == 200, f"Admin failed to create patient: {res.text}"

    # 3 Doctor tries to search = Should fail (Consent Withheld)
    print("   Doctor searching... (Expect 403)")
    res = client.get(f"/patient/search?sa_id={sa_id}", headers=doctor_headers)
    assert res.status_code == 403, f"Expected 403 Consent Withheld, got {res.status_code}"
    assert "Consent Withheld" in res.json()['detail']

    # 4 Doctor uses Break Glass = Should succeed
    print("   Doctor breaking glass... (Expect 200)")
    res = client.post("/emergency-summary", json={"sa_id": sa_id, "reason": "Unconscious"}, headers=doctor_headers)
    assert res.status_code == 200, f"Break Glass failed: {res.text}"
    assert res.json()['patient']['sa_id'] == sa_id

    # 5. Nurse tries to Add Patient = Should fail (RBAC)
    print("   Nurse trying to add patient... (Expect 403)")
    res = client.post("/patient/add", json=patient_data, headers=nurse_headers)
    assert res.status_code == 403, f"Nurse should not be able to add patient. Got {res.status_code}"
    
    print("   Paramedic trying to add patient... (Expect 403)")
    res = client.post("/patient/add", json=patient_data, headers=paramedic_headers)
    assert res.status_code == 403, f"Paramedic should not be able to add patient. Got {res.status_code}"
    
    print("✅ RBAC & Compliance Tests Passed!")

if __name__ == "__main__":
    test_rbac_and_consent()
