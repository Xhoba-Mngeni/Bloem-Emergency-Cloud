# Bloem Emergency Cloud (BEC)

**A Secure, AI-Powered Emergency Medical Summary System.**
*Built for the Bloemfontein Region to enable secure "Break-Glass" data access for emergency doctors.*

##  Key Features

* ** Rapid Patient Search:** Instant retrieval of critical medical history using SA ID Numbers.
* ** "Break-Glass" Protocol:** Restricted records (VIPs) and **Consent-Withheld** records are hidden by default and require a logged reason to access (Emergency Override).
* ** AI Safety Engine:** Automatically detects potentially fatal drug interactions and typo errors. Now includes **Explainability** (Why + Source + Confidence).
* ** Field-Level Encryption:** Sensitive patient data (Names, Allergies, Conditions) is encrypted at rest using Fernet (AES-128).
* ** Role-Based Access Control (RBAC):** Strict permissions for Admins, Doctors, Nurses, and Paramedics.
* ** Legal & Compliance:** Built-in POPIA consent enforcement and automated data retention policies (5-year archival).
* ** Audit Logging:** Every search, view, and override is immutably logged for legal accountability.
* ** Mobile First:** Optimized for tablet and mobile use in ambulances with high-contrast emergency UI.

##  Tech Stack

* **Backend:** Python 3.12, FastAPI
* **Database:** PostgreSQL (with `psycopg2` & connection pooling)
* **Security:** OAuth2 with JWT Tokens, Bcrypt Hashing, Fernet Encryption
* **Frontend:** Vanilla JS (SPA Architecture), HTML5, CSS3
* **AI Logic:** FuzzyWuzzy (String Matching) + Rule-Based Inference Engine

##  Quick Start (Local Dev)

**1. Prerequisites**
* Python 3.10+
* PostgreSQL installed and running locally.

**2. Installation**
```bash
# Clone the repository
git clone https://github.com/yourusername/emergency-summary-system.git

# Create Virtual Environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install Dependencies
pip install -r requirements.txt
```

**3. Setup Environment**
Create a `.env` file (see `.env.example`):
```ini
DB_NAME=emergency_db
DB_USER=postgres
DB_PASSWORD=
DB_HOST=127.0.0.1
DB_PORT=5433
DATABASE_URL=
JWT_SECRET_KEY=
JWT_REFRESH_SECRET_KEY=
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=10080
MASTER_ENCRYPTION_KEY=0000000000000000000000000000000000000000000000000000000000000000
```

**4. Initialize System**
Seeds database with encrypted dummy data and creates Admin user.
```bash
python src/setup_full_system.py
```

**5. Run Server**
```bash
uvicorn src.main:app --reload
```
Visit `http://localhost:8000` to access the login screen.

##  Environment & Secrets

- `MASTER_ENCRYPTION_KEY` is required and must be 64 hex characters (32 bytes). The app derives a valid Fernet key from this.
- `JWT_REFRESH_SECRET_KEY` is optional; if unset, refresh tokens use `JWT_SECRET_KEY`.
- You may set `DATABASE_URL` instead of individual DB_* variables.

**Generate a 64-hex MASTER_ENCRYPTION_KEY (Windows PowerShell):**
```powershell
[byte[]]$bytes = New-Object byte[] 32; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes); ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
```

**Generate a strong JWT secret (Windows PowerShell):**
```powershell
[Convert]::ToBase64String((1..48 | ForEach-Object {Get-Random -Minimum 0 -Maximum 256} | ForEach-Object {[byte]$_}))
```

**CI/CD (GitHub Actions) example:**
- Add repository secrets: `DB_PASSWORD`, `DATABASE_URL` or `DB_*`, `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `MASTER_ENCRYPTION_KEY`.
- Inject them as environment variables in your workflow:
```yaml
env:
  DB_HOST: 127.0.0.1
  DB_PORT: 5433
  DB_USER: postgres
  DB_NAME: emergency_db
  DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
  DATABASE_URL: ${{ secrets.DATABASE_URL }}
  JWT_SECRET_KEY: ${{ secrets.JWT_SECRET_KEY }}
  JWT_REFRESH_SECRET_KEY: ${{ secrets.JWT_REFRESH_SECRET_KEY }}
  MASTER_ENCRYPTION_KEY: ${{ secrets.MASTER_ENCRYPTION_KEY }}
```

##  Testing & Compliance

**Run Unit & Security Tests:**
```bash
pytest
```

**Run Compliance Audit (Retention Check):**
```bash
python src/compliance_manager.py
```

##  Default Users

| Role | Username | Password | Access |
|------|----------|----------|--------|
| **Admin** | `dr_xhoba` | `medical123` | Full Access, Logs, Stats |
| **Doctor** | `dr_strange` | `medical123` | Search, Add Patient, Break-Glass |
| **Nurse** | `nurse_joy` | `medical123` | Search, Break-Glass |
| **Paramedic** | `para_medic` | `medical123` | Search, Break-Glass |
