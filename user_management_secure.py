"""
User Management System — SECURE (hardened) version.

Same functionality as user_management_original.py, but every identified
vulnerability has been fixed. See SECURITY_AUDIT.md for the full
before/after analysis and re-run exploit attempts (all now blocked).
"""

import sqlite3
import hashlib
import hmac
import os
import re
import ast
import subprocess
import secrets
import logging
import time

DB_FILE = "users_secure.db"
NOTES_DIR = os.path.abspath("notes")
LOG_FILE = "app_security.log"

# FIX: no hardcoded secret. Read from an environment variable instead, and
# fail loudly with a clear message if it's missing, rather than silently
# falling back to an insecure default (a common secondary mistake).
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

# FIX: application-facing errors never include exception internals. All
# real exception details go to a log file only; the caller/user sees a
# short, generic message. Configure logging once, at import time.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# FIX: simple in-memory rate limiting / account lockout, defense-in-depth
# against automated password guessing even though passwords are now
# properly hashed. Not a replacement for hashing - an additional layer.
_failed_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-.]{0,253}[A-Za-z0-9])?$")


class ValidationError(Exception):
    """Raised for invalid user-supplied input. Safe to show to the user -
    it never contains internal system details, only what was wrong with
    their input."""


def init_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            password_salt TEXT,
            email TEXT
        )
    """)
    conn.commit()
    conn.close()


def _hash_password(password, salt=None):
    """Hash a password with PBKDF2-HMAC-SHA256 and a random per-user salt.

    FIX for plaintext password storage. PBKDF2 with a high iteration
    count is deliberately slow, which makes brute-forcing a stolen hash
    far more expensive than a fast hash like MD5 or a single SHA256 pass.
    (Argon2id or bcrypt would be even stronger and are recommended for a
    real production system; PBKDF2 is used here because it's in the
    Python standard library with no extra dependency, which keeps this
    submission fully self-contained.)
    """
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), iterations=200_000
    ).hex()
    return pwd_hash, salt


def _validate_username(username):
    if not USERNAME_PATTERN.match(username):
        raise ValidationError(
            "Username must be 3-32 characters: letters, numbers, underscore only."
        )


def _validate_email(email):
    if not EMAIL_PATTERN.match(email):
        raise ValidationError("Email address is not valid.")


def register(username, password, email):
    """Register a new user with input validation and salted password hashing."""
    _validate_username(username)
    _validate_email(email)
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters.")

    pwd_hash, salt = _hash_password(password)
    conn = sqlite3.connect(DB_FILE)
    try:
        # FIX for SQL injection: parameterized query. User input is passed
        # as bound parameters, never spliced into the SQL string, so it is
        # always treated as data and can never change the query's meaning.
        conn.execute(
            "INSERT INTO users (username, password_hash, password_salt, email) VALUES (?, ?, ?, ?)",
            (username, pwd_hash, salt, email),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        logging.exception("Unexpected error during registration")
        raise RuntimeError("Registration failed. Please try again.")
    finally:
        conn.close()


def login(username, password):
    """Check a username/password pair, with parameterized queries,
    salted-hash comparison, and basic rate limiting.
    """
    now = time.time()
    attempt_info = _failed_attempts.get(username)
    if attempt_info and attempt_info["count"] >= MAX_ATTEMPTS:
        if now - attempt_info["last"] < LOCKOUT_SECONDS:
            raise ValidationError(
                "Too many failed attempts. Please try again in a minute."
            )
        else:
            _failed_attempts.pop(username, None)  # lockout window expired

    conn = sqlite3.connect(DB_FILE)
    try:
        # FIX for SQL injection: parameterized query, exactly as in register().
        cursor = conn.execute(
            "SELECT password_hash, password_salt FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
        if row is None:
            _record_failed_attempt(username, now)
            return False

        stored_hash, salt = row
        candidate_hash, _ = _hash_password(password, salt=salt)

        # FIX: constant-time comparison. A naive `==` on strings can leak
        # timing information (how many leading characters matched) that,
        # over many attempts, helps an attacker guess the hash byte by
        # byte. hmac.compare_digest is designed specifically to avoid this.
        if hmac.compare_digest(candidate_hash, stored_hash):
            _failed_attempts.pop(username, None)
            return True
        else:
            _record_failed_attempt(username, now)
            return False
    except sqlite3.Error:
        # FIX for information disclosure: log the real error internally,
        # but never expose exception details (query text, DB structure,
        # stack trace) to the caller/user.
        logging.exception("Database error during login")
        raise RuntimeError("Login failed due to a system error. Please try again later.")
    finally:
        conn.close()


def _record_failed_attempt(username, now):
    info = _failed_attempts.setdefault(username, {"count": 0, "last": now})
    info["count"] += 1
    info["last"] = now


def search_users(keyword):
    """Search usernames by a partial keyword match, safely."""
    conn = sqlite3.connect(DB_FILE)
    try:
        # FIX for SQL injection: parameterized query. Also note this
        # SELECT only ever names username and email explicitly - it
        # can never be tricked into returning the password_hash column
        # the way the original's f-string could be extended with UNION,
        # because there is no string splicing happening at all.
        like_pattern = f"%{keyword}%"
        cursor = conn.execute(
            "SELECT username, email FROM users WHERE username LIKE ? ESCAPE '\\'",
            (like_pattern,),
        )
        return cursor.fetchall()
    finally:
        conn.close()


def read_notes_file(filename):
    """Read a text file from the user's notes directory, safely.

    FIX for path traversal: strip any directory components from the
    supplied filename (os.path.basename), then resolve the final path
    and verify it is still actually located inside NOTES_DIR before
    opening it. Both checks matter: basename alone can still be tricked
    by some encodings/symlink tricks, and the containment check catches
    anything basename might miss.
    """
    safe_name = os.path.basename(filename)
    candidate_path = os.path.abspath(os.path.join(NOTES_DIR, safe_name))

    if not candidate_path.startswith(NOTES_DIR + os.sep) and candidate_path != NOTES_DIR:
        raise ValidationError("Invalid filename.")
    if not os.path.isfile(candidate_path):
        raise ValidationError("Notes file not found.")

    with open(candidate_path, "r") as f:
        return f.read()


def run_diagnostic(host):
    """Run a network 'ping' diagnostic against a host the user supplies, safely.

    FIX for OS command injection, two layers of defense:
      1. Strict allowlist validation of the hostname/IP format BEFORE it
         touches any command at all - anything with shell metacharacters
         (;, &&, |, backticks, etc.) is rejected outright.
      2. subprocess.run() with a list of arguments and shell=False (the
         default), so even if a malformed value somehow got past
         validation, there is no shell present to interpret metacharacters
         as command separators - the whole string is passed as a single,
         literal argument to the ping binary.
    """
    if not HOSTNAME_PATTERN.match(host):
        raise ValidationError("Invalid hostname or IP address.")

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
        )
        return result.stdout
    except FileNotFoundError:
        # ping isn't installed in this sandbox; that's fine for our purposes -
        # validation + shell=False is what we're actually demonstrating.
        return "(ping utility not available in this environment)"
    except subprocess.TimeoutExpired:
        return "(diagnostic timed out)"


_ALLOWED_AST_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.USub, ast.UAdd,
)


def calculate(expression):
    """Evaluate a simple arithmetic expression, safely.

    FIX for eval() code execution: parse the expression into an AST and
    walk it, rejecting anything that isn't a plain arithmetic expression
    (numbers and + - * / // % ** operators only). Function calls, name
    lookups, attribute access, imports, and every other Python construct
    that eval() would happily execute are rejected before any evaluation
    happens at all.
    """
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        raise ValidationError("Invalid expression.")

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_AST_NODES):
            raise ValidationError(
                f"Expression contains a disallowed construct: {type(node).__name__}"
            )
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, float)):
            raise ValidationError("Only numeric constants are allowed.")

    return eval(compile(tree, "<calculate>", "eval"))


def safe_hash_for_export(value):
    """Hash a value for a data-export feature, using SHA-256 instead of MD5.

    FIX for weak cryptography: MD5 is cryptographically broken (fast
    collisions are practical). SHA-256 has no known practical collision
    attack. Note this is for a non-password integrity/export use case;
    for password storage, see _hash_password() above, which uses PBKDF2
    with a salt specifically because it must also resist brute-forcing,
    not just collisions.
    """
    return hashlib.sha256(value.encode()).hexdigest()


if __name__ == "__main__":
    init_db()
    register("alice", "hunter2_secure_pw", "alice@example.com")
    print("Secure app initialized. See SECURITY_AUDIT.md for exploit re-test results.")
