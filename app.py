import os
import re
import secrets
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, abort
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt

import db

app = Flask(__name__)

# Secret key for session management
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "super-secret-production-key-change-in-prod")

# Security configuration for session cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set to True if serving over HTTPS in production
app.config["SESSION_COOKIE_SECURE"] = False

# Hardening: Application-level Pepper (kept outside the database)
PEPPER = os.environ.get("PASSWORD_PEPPER", "PepperKey!2026#SecureLoginLab").encode("utf-8")

# Hardening: Rate limiting per IP to prevent automated brute-force attacks
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# CSRF helper functions
def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token

def verify_csrf_token():
    token = request.form.get("csrf_token")
    if not token or token != session.get("_csrf_token"):
        abort(400, description="Invalid or missing CSRF token.")

# Decorator to restrict routes to logged-in users only
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# Password policy validator
def validate_password_strength(password: str):
    """
    Validates password against strong security policy:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 numerical digit
    - At least 1 special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one digit (0-9)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must include at least one special character (!@#$%^&*...)."
    return True, ""


# -------------------- ROUTES --------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        verify_csrf_token()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")

        if len(username) < 3 or len(username) > 30:
            flash("Username must be between 3 and 30 characters.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            flash(error_msg, "danger")
            return render_template("register.html")

        # Check if username already exists
        existing_user = db.get_user_by_username(username)
        if existing_user:
            flash("Username is already taken. Please choose another.", "danger")
            return render_template("register.html")

        # Combine password with secret pepper and generate salted bcrypt hash (cost factor 12)
        password_bytes = password.encode("utf-8") + PEPPER
        salt = bcrypt.gensalt(rounds=12)
        hashed_bytes = bcrypt.hashpw(password_bytes, salt)
        password_hash_str = hashed_bytes.decode("utf-8")

        # Store in database
        success = db.create_user(username, password_hash_str)
        if success:
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("An error occurred while creating your account. Try again.", "danger")
            return render_template("register.html")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        verify_csrf_token()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("login.html")

        # Fetch user safely using parameterized query (prevents SQLi)
        user = db.get_user_by_username(username)

        # Check lockout first if user exists
        if user:
            is_locked, remaining_minutes = db.is_account_locked(user)
            if is_locked:
                flash(
                    f"Account is temporarily locked due to excessive failed attempts. "
                    f"Please try again in approximately {remaining_minutes} minute(s).",
                    "danger"
                )
                return render_template("login.html")

        # Verify password constant-time using bcrypt.checkpw
        authenticated = False
        if user:
            password_bytes = password.encode("utf-8") + PEPPER
            stored_hash_bytes = user["password_hash"].encode("utf-8")
            if bcrypt.checkpw(password_bytes, stored_hash_bytes):
                authenticated = True

        if authenticated:
            # Reset failed login count and clear lock status
            db.reset_failed_attempts(username)

            # Establish secure session
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}! You have logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            # Login failed: handle counter and lockout if user exists
            if user:
                attempts, is_now_locked, _ = db.increment_failed_attempts(username, max_attempts=5, lockout_minutes=10)
                if is_now_locked:
                    flash(
                        "Account has been locked for 10 minutes due to 5 consecutive failed login attempts.",
                        "danger"
                    )
                    return render_template("login.html")
                else:
                    remaining_attempts = 5 - attempts
                    flash(
                        f"Invalid username or password. ({remaining_attempts} attempt(s) remaining before lockout)",
                        "danger"
                    )
                    return render_template("login.html")
            else:
                # Generic message to prevent user enumeration
                flash("Invalid username or password.", "danger")
                return render_template("login.html")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/inspect-db")
def inspect_db():
    """
    Inspection helper route for assignment demonstration.
    Displays database rows so the student can capture a screenshot of
    passwords stored in protected/hashed form (bcrypt $2b$12$...).
    """
    users = db.get_all_users()
    return render_template("inspect_db.html", users=users)


if __name__ == "__main__":
    # Ensure database is initialized before running
    if not os.path.exists(db.DATABASE_PATH):
        db.init_db()
        print("[*] Database initialized successfully.")
    
    print("[*] Starting Secure Login App at http://127.0.0.1:5000 ...")
    app.run(debug=True, port=5000)
