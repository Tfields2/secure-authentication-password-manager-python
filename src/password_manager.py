# =========================
# Imports
# =========================
import hashlib              # Cryptographic hashing
import getpass              # Secure password input (no echo)
import hmac                 # Constant-time comparisons
import os                   # OS-level utilities (env vars, random bytes)
import json                 # Persistent storage
from pathlib import Path    # File path handling
import time                 # Time-based lockouts and timestamps


# =========================
# Security / Behavior Config
# =========================
ITERATIONS = 100000          # PBKDF2 iterations (slows brute-force)
SALT_BYTES = 16              # Salt size for hashing
DK_BYTES = 32                # 256-bit derived key
MAX_FAILS = 5                # Failed login attempts before lockout
LOCK_SECONDS = 300           # Lockout duration (seconds)

LOG_FILE_PATH = Path("auth_audit.log")     # Audit log file
ADMIN_KEY_ENV = "PM_ADMIN_KEY"              # Env var holding admin reset key
data_file_path = Path("password_manager.json")  # User database file


# =========================
# In-memory User Store
# =========================
password_manager = {}  # Loaded from disk on startup


# =========================
# Input Validation Helpers
# =========================
def is_empty_username(username):
    """Reject empty or whitespace-only usernames."""
    if not username or not username.strip():
        print("Username cannot be empty. Please try again.")
        return True
    return False

def is_empty_password(password):
    """Reject empty or whitespace-only passwords."""
    if not password or not password.strip():
        print("Password cannot be empty. Please try again.")
        return True
    return False


# =========================
# Account Creation
# =========================
def create_account():
    """Create a new user with securely hashed password."""
    username = input("Enter your username: ")
    if is_empty_username(username):
        return

    username = username.strip().lower()

    # Prevent duplicate usernames
    if username in password_manager:
        print("Username already exists. Please choose a different username.")
        return

    password = getpass.getpass("Enter your password: ")
    if is_empty_password(password):
        return

    # Hash password with unique salt
    salt_hex, dk_hex = hash_password(password)

    # Store account record
    password_manager[username] = {
        'salt': salt_hex,
        'dk': dk_hex,
        'fails': 0,
        'lock_until': 0
    }

    save_users()
    log_auth_event("create_account", username, True, "ok")
    print("Account created successfully!")


# =========================
# Login Flow
# =========================
def login():
    """Authenticate user with retry loop and lockout protection."""
    username = input("Enter your username: ")
    if is_empty_username(username):
        return
    username = username.strip().lower()

    record = password_manager.get(username)

    # Reject missing or malformed user records
    if not isinstance(record, dict) or 'salt' not in record or 'dk' not in record:
        log_auth_event("login", username, False, "unknown_user_or_bad_record")
        print("Invalid username or password.")
        return

    # Check account lockout
    lock_until = record.get("lock_until", 0)
    now = time.time()
    if lock_until and now < lock_until:
        remaining = int(lock_until - now)
        log_auth_event("login", username, False, "locked")
        print(f"Account locked. Please try again in {remaining} seconds.")
        return

    salt_hex = record['salt']
    stored_dk_hex = record['dk']

    # Password retry loop (does not restart program)
    while True:
        password = getpass.getpass("Enter your password: ")
        if is_empty_password(password):
            print("Password cannot be empty.")
            continue

        # Correct password
        if verify_password(password, salt_hex, stored_dk_hex):
            log_auth_event("login", username, True, "ok")
            print("Login successful!")
            record["fails"] = 0
            record["lock_until"] = 0
            save_users()
            return

        # Wrong password
        record["fails"] = int(record.get("fails", 0)) + 1
        log_auth_event("login", username, False, "bad_password")

        # Lock account after too many failures
        if record["fails"] >= MAX_FAILS:
            record["lock_until"] = time.time() + LOCK_SECONDS
            record["fails"] = 0
            save_users()
            print(f"Too many failed login attempts. Account locked for {LOCK_SECONDS} seconds.")
            return

        save_users()
        print("Invalid password. Please try again.")


# =========================
# Password Hashing
# =========================
def hash_password(password: str) -> tuple[str, str]:
    """Hash password with PBKDF2-HMAC-SHA256 and random salt."""
    salt = os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=DK_BYTES
    )
    return salt.hex(), dk.hex()

def verify_password(password: str, salt_hex: str, stored_hash_hex: str) -> bool:
    """Verify password using constant-time comparison."""
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=DK_BYTES
    )
    return hmac.compare_digest(dk.hex(), stored_hash_hex)


# =========================
# Main Menu Loop
# =========================
def main():
    """Primary user menu."""
    while True:
        print("\n1. Create Account, 2. Login, 3. Reset Password (Admin), 4. Delete User (Admin), 5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            create_account()
        elif choice == '2':
            login()
        elif choice == '3':
            forgot_password_reset()
        elif choice == '4':
            admin_delete_user()
        elif choice == '5':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")


# =========================
# Persistence
# =========================
def load_users():
    """Load users from disk and normalize fields."""
    global password_manager

    if not data_file_path.exists():
        password_manager = {}
        return

    try:
        with data_file_path.open("r", encoding="utf-8") as file:
            password_manager = json.load(file)

        # Normalize numeric fields
        for rec in password_manager.values():
            if isinstance(rec, dict) and "salt" in rec and "dk" in rec:
                rec.setdefault("fails", 0)
                rec.setdefault("lock_until", 0)
                try:
                    rec["fails"] = int(rec.get("fails", 0))
                except (ValueError, TypeError):
                    rec["fails"] = 0
                try:
                    rec["lock_until"] = float(rec.get("lock_until", 0))
                except (ValueError, TypeError):
                    rec["lock_until"] = 0.0
    except (json.JSONDecodeError, OSError):
        print("Warning: user data corrupted, starting fresh.")
        password_manager = {}

def save_users():
    """Atomically save users to disk to prevent corruption."""
    try:
        temp_path = data_file_path.with_suffix(".tmp")

        if temp_path.exists():
            temp_path.unlink()

        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(password_manager, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        temp_path.replace(data_file_path)

    except OSError as e:
        print(f"Failed to save users: {e}")


# =========================
# Audit Logging
# =========================
def log_auth_event(event_type: str, username: str, success: bool, reason: str = ""):
    """Write authentication events to append-only audit log."""
    entry = {
        "ts": time.time(),
        "event": event_type,
        "username": username,
        "success": success,
        "reason": reason
    }
    try:
        with LOG_FILE_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        print(f"Failed to write audit log: {e}")


# =========================
# Admin Password Reset
# =========================
def forgot_password_reset():
    """Admin-only password reset with confirmation loop."""
    username = input("Enter username to reset: ")
    if is_empty_username(username):
        return
    username = username.strip().lower()

    record = password_manager.get(username)
    if not isinstance(record, dict) or "salt" not in record or "dk" not in record:
        print("Account not found.")
        log_auth_event("password_reset", username, False, "not_found")
        return

    admin_key = getpass.getpass("Enter admin reset key: ")
    expected = os.environ.get(ADMIN_KEY_ENV)

    if not expected or not hmac.compare_digest(admin_key, expected):
        print("Reset denied.")
        log_auth_event("password_reset", username, False, "bad_admin_key")
        return

    # Require password confirmation
    while True:
        new_password = getpass.getpass("Enter new password: ")
        if is_empty_password(new_password):
            continue

        confirm = getpass.getpass("Confirm new password: ")
        if new_password != confirm:
            print("Passwords do not match. Try again.")
            continue
        break

    # Reset credentials and unlock account
    salt_hex, dk_hex = hash_password(new_password)
    record.update({
        "salt": salt_hex,
        "dk": dk_hex,
        "fails": 0,
        "lock_until": 0
    })

    save_users()
    print("Password reset successfully!")
    log_auth_event("password_reset", username, True, "ok")

def admin_delete_user():
    """Admin-only delete user with confirmation."""
    username = input("Enter username to delete: ")
    if is_empty_username(username):
        return
    username = username.strip().lower()

    record = password_manager.get(username)
    if not isinstance(record, dict) or "salt" not in record or "dk" not in record:
        print("Account not found.")
        log_auth_event("delete_user", username, False, "not_found")
        return

    admin_key = getpass.getpass("Enter admin key: ")
    expected = os.environ.get(ADMIN_KEY_ENV)

    if not expected or not hmac.compare_digest(admin_key, expected):
        print("Delete denied.")
        log_auth_event("delete_user", username, False, "bad_admin_key")
        return

    confirm = input(f"Type DELETE to confirm deleting '{username}': ").strip()
    if confirm != "DELETE":
        print("Delete canceled.")
        log_auth_event("delete_user", username, False, "canceled")
        return

    del password_manager[username]
    save_users()
    print("User deleted successfully.")
    log_auth_event("delete_user", username, True, "ok")



# =========================
# Program Entry Point
# =========================
if __name__ == "__main__":
    load_users()
    main()

