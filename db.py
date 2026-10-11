import sqlite3
import os
from datetime import datetime, timedelta

DATABASE_PATH = os.path.join(os.path.dirname(__file__), "database.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

def get_db():
    """Connect to SQLite database with Row factory for named column access."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables using schema.sql."""
    conn = get_db()
    with open(SCHEMA_PATH, mode="r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

def get_user_by_username(username: str):
    """
    Fetch a user record safely using a parameterized query.
    Protects against SQL Injection attacks like: ' OR 1=1 --
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(username: str, password_hash: str):
    """Insert a new user with hashed password."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, failed_attempts, locked_until) VALUES (?, ?, 0, NULL)",
            (username, password_hash)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def increment_failed_attempts(username: str, max_attempts: int = 5, lockout_minutes: int = 10):
    """
    Increment failed login count. If it reaches max_attempts, set locked_until timestamp.
    Returns: (new_attempts_count, is_now_locked, locked_until_str)
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return (0, False, None)

    current_attempts = row["failed_attempts"] + 1
    locked_until_str = None
    is_now_locked = False

    if current_attempts >= max_attempts:
        lockout_time = datetime.now() + timedelta(minutes=lockout_minutes)
        locked_until_str = lockout_time.strftime("%Y-%m-%d %H:%M:%S")
        is_now_locked = True
        cursor.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (current_attempts, locked_until_str, username)
        )
    else:
        cursor.execute(
            "UPDATE users SET failed_attempts = ? WHERE username = ?",
            (current_attempts, username)
        )

    conn.commit()
    conn.close()
    return (current_attempts, is_now_locked, locked_until_str)

def reset_failed_attempts(username: str):
    """Reset failed attempts and unlock account upon successful login."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()

def is_account_locked(user_row):
    """
    Check if an account is currently locked out.
    If lockout period has expired, reset counter and unlock automatically.
    """
    if not user_row["locked_until"]:
        return False, None

    lockout_until = datetime.strptime(user_row["locked_until"], "%Y-%m-%d %H:%M:%S")
    now = datetime.now()

    if now < lockout_until:
        remaining_minutes = int((lockout_until - now).total_seconds() // 60) + 1
        return True, remaining_minutes
    else:
        # Lockout period expired: auto-reset
        reset_failed_attempts(user_row["username"])
        return False, None

def get_all_users():
    """Retrieve all users to demonstrate hashed passwords stored in database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, failed_attempts, locked_until, created_at FROM users")
    users = cursor.fetchall()
    conn.close()
    return users
