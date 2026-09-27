"""
User Management System — ORIGINAL (vulnerable) version.

A small CLI application for a fictional internal tool: users can register,
log in, search the user directory, read a personal notes file, run a
network diagnostic, and use a quick calculator.

This version is written the way a rushed first draft often is: it works,
but it has several real, exploitable security vulnerabilities left in.
See SECURITY_AUDIT.md for the full analysis and PoC exploits.

DO NOT deploy this file. It exists to be audited and fixed.
"""

import sqlite3
import hashlib
import os

DB_FILE = "users_original.db"

# VULNERABILITY: hardcoded secret committed directly in source code.
ADMIN_API_KEY = "sk_live_9f8a7b6c5d4e3f2a1b0c"


def init_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT
        )
    """)
    conn.commit()
    conn.close()


def register(username, password, email):
    """Register a new user.

    VULNERABILITY: password is stored in plain text. Anyone who reads the
    database file (a backup, a leaked file, an insider, a second SQL
    injection elsewhere) gets every user's real password immediately -
    and because people reuse passwords, that compromises their accounts
    on other sites too.
    """
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, password, email),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def login(username, password):
    """Check a username/password pair against the database.

    VULNERABILITY: SQL Injection. The query is built with an f-string,
    directly splicing user input into SQL syntax. An attacker can submit
    a username like:  admin' --
    which turns the query into:
        SELECT * FROM users WHERE username='admin' --' AND password='...'
    The -- comments out the rest of the query, so the password check
    never happens at all — instant login bypass with no valid password.
    """
    conn = sqlite3.connect(DB_FILE)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cursor = conn.execute(query)
        row = cursor.fetchone()
        return row is not None
    except Exception as e:
        # VULNERABILITY: improper error handling / information disclosure.
        # Printing the raw exception (including the failed SQL) to the
        # user leaks internal implementation details - table structure,
        # query shape, and even a stack trace - that an attacker can use
        # to refine further attacks.
        print(f"Login error: {e}")
        return False
    finally:
        conn.close()


def search_users(keyword):
    """Search usernames by a partial keyword match.

    VULNERABILITY: same SQL Injection pattern as login() - user input is
    spliced directly into the query string, so a crafted keyword can
    change the query's meaning entirely (e.g. exfiltrate all rows,
    or every column including the plaintext password column).
    """
    conn = sqlite3.connect(DB_FILE)
    query = f"SELECT username, email FROM users WHERE username LIKE '%{keyword}%'"
    try:
        cursor = conn.execute(query)
        return cursor.fetchall()
    finally:
        conn.close()


def read_notes_file(filename):
    """Read a text file from the user's notes directory.

    VULNERABILITY: Path Traversal. filename is joined directly onto the
    notes directory with no validation, so an attacker can pass something
    like "../../../etc/passwd" and read arbitrary files on the filesystem
    that the running process has permission to access.
    """
    path = os.path.join("notes", filename)
    with open(path, "r") as f:
        return f.read()


def run_diagnostic(host):
    """Run a network 'ping' diagnostic against a host the user supplies.

    VULNERABILITY: OS Command Injection. host is passed straight into a
    shell command via os.system(). An attacker can chain arbitrary shell
    commands using characters like ; or && , e.g.:
        127.0.0.1; touch /tmp/pwned
    which runs "touch /tmp/pwned" with the full privileges of this
    process, completely unrelated to "pinging" anything.
    """
    command = f"ping -c 1 {host}"
    os.system(command)


def calculate(expression):
    """Evaluate a simple math expression typed by the user.

    VULNERABILITY: use of eval() on untrusted input allows arbitrary
    Python code execution, not just arithmetic. An attacker can submit
    something like:
        __import__('os').system('touch /tmp/pwned_eval')
    and it runs with the full privileges of this process.
    """
    return eval(expression)


def weak_hash_for_export(value):
    """Hash a value for a data-export feature.

    VULNERABILITY: MD5 is a cryptographically broken hash function -
    fast collision attacks exist and it should never be used for any
    security-relevant purpose (integrity checks, password storage,
    deduplication of sensitive tokens, etc).
    """
    return hashlib.md5(value.encode()).hexdigest()


if __name__ == "__main__":
    init_db()
    register("alice", "hunter2", "alice@example.com")
    print("Original vulnerable app initialized. See SECURITY_AUDIT.md for exploit demonstrations.")
