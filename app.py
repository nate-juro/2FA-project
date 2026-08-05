import io
import base64
import sqlite3
import re
from datetime import datetime, timedelta
from pathlib import Path

import pyotp
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_wtf import CSRFProtect
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError

base_dir = Path(__file__).parent
db_path = base_dir / "schema.db"
schema_path = base_dir / "schema.sql"
lockout_threashold = 5
lockout_minutes = 15

app = Flask(__name__)

app.config["SECRET_KEY"] = "dev-only-change-this-before-real-deployment"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

csrf = CSRFProtect(app)
ph = PasswordHasher()

# Database Helpers

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        with open(schema_path) as f:
            g.db.executescript(f.read())
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def log_event(username: str, event: str):
    db = get_db()
    db.execute(
        "insert into login_log (username, event, ip_address) values (?, ?, ?)",
        (username, event, request.remote_addr),
    )
    db.commit()

# Validation

def validate_username(username):
    if not username or len(username) <3 or len(username) > 40:
        return "Username must be 3-40 characters."
    if not re.match(r"^[A-Za-z0-9_]+$", username):
        return "Username can only contain letters, numbers, and underscores."
    return None

def validate_email(email):
    if not email or len(email) > 40:
        return "email is required and must be 40 characters or fewer."
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return "Email format looks invalid."
    return None

def validate_password(password):
    if len(password) <12:
        return "Password must be at least 12 characters."
    return None

# Registration

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    if password != confirm:
        flash("Passwords do not match.")
        return render_template("register.html")

    for error in (validate_username(username), validate_email(email), validate_password(password)):
        if error:
            flash(error)
            return render_template("register.html")

    db = get_db()
    existing = db.execute(
        "select 1 from users where username = ? or email = ?", (username, email)
    ).fetchone()
    if existing:
        flash("Username or email already registered.")
        return render_template("register.html")

    try:
        password_hash = ph.hash(password)
    except HashingError:
        flash("Could not process password. Try again.")
        return render_template("register.html")

    db.execute(
        "insert into users (username, email, password_hash) values (?, ?, ?)",
        (username, email, password_hash),
    )
    db.commit()
    log_event(username, "registered")

    session["setup_username"] = username
    return redirect(url_for("setup_2fa"))

# 2FA Setup

@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    username = session.get("setup_username")
    if not username:
        flash("Reigster or log in first.")
        return redirect(url_for("register"))

    db = get_db()
    user = db.execute("select * from users where username = ?", (username,)).fetchone()

    if request.method == "GET":
        if not user["totp_secret"]:
            secret = pyotp.random_base32()
            db.execute("update users set totp_secret = ? where username = ?", (secret, username))
            db.commit()
        else:
            secret = user["totp_secret"]

        url = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureLoginDemo")
        qr_img = qrcode.make(url)
        buf = io.BytesIO()
        qr_img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return render_template("setup_2fa.html", qr_b64=qr_b64, secret = secret)

    code = request.form.get("code", "")
    totp = pyotp.TOTP(user["totp_secret"])
    if totp.verify(code, valid_window=2):
        db.execute("update users set totp_confirmed = 1 where username = ?", (username,))
        db.commit()
        log_event(username, "2fa_enabled")
        session.pop("setup_username", None)
        flash("2FA enabled. You can now log in.")
        return redirect(url_for("login"))

    flash("that code didn't match. Try again.")
    return redirect(url_for("setup_2fa"))

# Login

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    db = get_db()
    user = db.execute("select * from users where username = ?", (username,)).fetchone()

    generic_error = "Invalid username or password."

    if user is None:
        log_event(username, "password_fail_unknown_user")
        flash(generic_error)
        return render_template("login.html")

    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.now() < locked_until:
            log_event(username, "login_blocked_locked")
            flash(f"Account locked until {locked_until.strftime('%H:%M:%S')}. Try again later.")
            return render_template("login.html")

    try:
        ph.verify(user["password_hash"], password)
    except VerifyMismatchError:
        attempts = user["failed_attempts"] + 1
        if attempts >= lockout_threashold:
            locked_until = (datetime.now() + timedelta(minutes=lockout_minutes)).isoformat()
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                (attempts, locked_until, username),
            )
            log_event(username, "locked")
        else:
            db.execute(
                "UPDATE users SET failed_attempts = ? WHERE username = ?", (attempts, username)
            )
            log_event(username, "password_fail")
        db.commit()
        flash(generic_error)
        return render_template("login.html")


    db.execute(
        "update users set failed_attempts = 0, locked_until = null where username = ?",
        (username,),
    )
    db.commit()
    log_event(username, "password_ok")

    if not user["totp_confirmed"]:
        session["setup_username"] = username
        return redirect(url_for("setup_2fa"))

    session["pending_2fa_username"] = username
    flash("Please finish setting up 2FA before logging in.")
    return redirect(url_for("verify_2fa"))

@app.route("/login/verify", methods=["GET", "POST"])
def verify_2fa():
    username = session.get("pending_2fa_username")
    if not username:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("verify_2fa.html")

    db = get_db()
    user = db.execute("select * from users where username = ?", (username,)).fetchone()
    code = request.form.get("code", "")
    totp = pyotp.TOTP(user["totp_secret"])

    if totp.verify(code, valid_window=1):
        log_event(username, "2fa_ok")
        session.clear()
        session["user_id"] = user["user_id"]
        session["username"] = user["username"]
        return redirect(url_for("dashboard"))

    log_event(username, "2fa_fail")
    flash("Invalid code. Try again.")
    return render_template("verify_2fa.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    if username:
        log_event(username, "logout")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)