# Secure Login System & Password Protection Lab

A complete implementation of a secure authentication website demonstrating password protection techniques against cracking attacks.

---

## 📁 Project Structure

```text
secure-login/
├── app.py              # Flask web server, auth routes, lockout logic, CSRF & rate limiting
├── db.py               # SQLite helpers & parameterized queries (SQLi protection)
├── schema.sql          # Database schema (users table)
├── database.db         # SQLite database file (created automatically)
├── crack_demo.py       # Benchmarking & cracking demonstration (SHA-256 vs Bcrypt Cost 12)
├── test_app.py         # Automated test suite (5 tests covering all security requirements)
├── requirements.txt    # Python dependencies
├── static/
│   └── style.css       # Clean, modern stylesheet
└── templates/
    ├── base.html       # Base layout with navigation
    ├── login.html      # Login page with lockout warnings
    ├── register.html   # Registration page with password policy checklist
    ├── dashboard.html  # Protected dashboard (accessible only when authenticated)
    └── inspect_db.html # Database inspector to capture screenshots of hashed passwords
```

---

## 🚀 Quick Start Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Seed Database & Run Security Demonstrations
```bash
python crack_demo.py
```
This script will:
- Initialize `database.db`.
- Pre-seed two test users: `alice` and `bob` (both with password: `LabPassword@2026`).
- Demonstrate **Proof of Salting** (same password produces two different hashes).
- Benchmark **Cracking Speed** (shows Bcrypt is ~170,000x slower than raw SHA-256).
- Test **SQL Injection Resistance** with payload `' OR 1=1 --`.

### 3. Run the Web Application
```bash
python app.py
```
Open your browser at: **`http://127.0.0.1:5000`**

---

## 📸 Guide to Required Submission Outputs & Screenshots

| Output Required | How to Generate & Capture |
| :--- | :--- |
| **1. Login page screenshot** | Navigate to `http://127.0.0.1:5000/login` and take a screenshot of the login form. |
| **2. Protected/hashed password screenshot** | Navigate to `http://127.0.0.1:5000/inspect-db`. You will see `alice`, `bob`, and any other user with their password hashes displayed as `$2b$12$...`. |
| **3. Successful login output** | Log in with: <br>• **Username:** `alice`<br>• **Password:** `LabPassword@2026`<br>Take a screenshot of the resulting dashboard (`http://127.0.0.1:5000/dashboard`). |
| **4. Incorrect password output** | Attempt to log in with an incorrect password (e.g. `WrongPass!123`). Take a screenshot of the flash alert showing remaining attempts before lockout. Repeat 5 times to show the **Account Locked** message. |
| **5. Source Code** | Include `app.py`, `db.py`, `schema.sql`, `templates/`, and `crack_demo.py`. |

---

## 🔒 Security Techniques Implemented

1. **Slow Cryptographic Hashing with Adaptive Work Factor:**
   - Implemented via `bcrypt` with cost factor 12 ($2^{12} = 4096$ rounds).
   - Prevents GPU/ASIC acceleration of brute-force and dictionary attacks.
2. **Cryptographically Secure Salting:**
   - Automatically generated 128-bit random salt per user.
   - Thwarts pre-computed Rainbow Table attacks.
3. **Application-level Pepper:**
   - Secret key stored outside the database appended to passwords before hashing.
4. **Account Lockout & Brute-Force Counter:**
   - Locks user account for 10 minutes after 5 consecutive failed attempts.
5. **IP Rate Limiting:**
   - Limits login requests to 10 attempts per minute per IP using `flask-limiter`.
6. **SQL Injection Defense:**
   - Strict use of parameterized SQL queries (`?` placeholders).
7. **Session Hardening:**
   - `HttpOnly=True` session cookies (prevents client-side script theft via XSS).
   - `SameSite=Lax` (prevents cross-site request forgery).
   - CSRF tokens verified on all form submissions.
