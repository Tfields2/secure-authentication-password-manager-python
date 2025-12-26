# Secure Authentication & Password Manager (Python)
## Overview
This project began as a **basic password manager** and was incrementally hardened into a **secure authenticated system**. The goal was to understand how **real world password managers** implement cryptographic protection, account security controls, and auditability. Through **iterative developemnent**, I introduced controls commonly used in production systems, including password hashing, account lockouts, audit logging, administrative actions, and safe persistence. This project emphasizes **hands on Python security engineering**, not theoretical knowledge.

---
## How to Run

Before running the application, set the **admin reset key** as an environment variable. This key is required for administrative actions such as password resets and user deletion.

### macOS / Linux
```bash
export PM_ADMIN_KEY="your-strong-admin-secret"
python src/password_manager.py
```
### Windows (Powershell)
```bash
setx PM_ADMIN_KEY "your-strong-admin-secret"
python src/password_manager.py
```
---

## Key Security Features Implemented

### Password Hashing (PBKDF-HMAC-SHA256)

- Passwords are **never stored in plaintext**
- Unique **random salt per user**
- Configurable iteration count to slow brute-force attacks
- Constant-time comparisons via `hmac.compare_digest`

**Why it matters:**  
Protects credentials even if the database is compromised.

---

### Account Lockout Protection

- Accounts lock after repeated failed logins
- Tracks failed attempts per user
- Locks account after `MAX_FAILS`
- Time-based unlock mechanism
- Automatically resets after successful login or password reset

**Why it matters:**  
Prevents brute-force and credential-stuffing attacks.

---

### Login Retry Loop (Security + User Experience)

- Incorrect passwords do **not crash or restart** the program
- Controlled retry loop inside the login function
- Still increments failed-attempt counters
- Lockout enforcement remains intact

**Why it matters:**  
Improves usability without weakening security.

---

### Authentication Audit Logging

- Every sensitive action is logged

Logged events include:
- Login success / failure
- Account lockouts
- Password resets
- User deletions
- Admin authentication failures

Log properties:
- Append-only
- Structured JSON
- Timestamped

**Why it matters:**  
Audit logs are essential for incident response and digital forensics.

---

### Admin-Controlled Password Reset

- Privileged password reset path
- Protected by environment-variable admin key
- Password confirmation loop
- Automatically resets account lockout state
- Fully audited

**Why it matters:**  
Simulates real enterprise recovery workflows.

---

### Admin User Deletion

- Secure removal of user accounts
- Admin authentication required
- Explicit confirmation step
- Safe persistence
- Fully logged

**Why it matters:**  
Demonstrates role-based privilege separation.

---

### Safe Persistent Storage (Atomic Writes)

- User data stored safely on disk
- Written to temporary file
- Flushed and synced to disk
- Atomically replaces original file
- Handles corruption gracefully

**Why it matters:**  
Prevents data loss during crashes or power failures.

---

## Security Concepts Practiced

- Password hashing vs encryption
- Salting & key stretching
- Constant-time cryptographic comparisons
- Authentication audit logging
- Account lockout strategies
- Privilege separation (admin vs user)
- Secure file I/O patterns
- Defensive input validation

---

## Technologies Used

- **Python 3**
- `hashlib`, `hmac`, `getpass`
- JSON persistence
- OS environment variables
- File system hardening techniques

---

## Notes

Sensitive files such as credential databases, logs, and environment variables are **excluded from version control** using `.gitignore`.

This project was designed for **educational and portfolio purposes** to demonstrate secure coding practices.
