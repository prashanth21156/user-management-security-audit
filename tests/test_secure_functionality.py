"""
Functional tests for the secure application: proves that hardening the
app did not break legitimate functionality. Security fixes are only
useful if the app still works correctly for real users.
"""

import os
import pytest
import user_management_secure as secure


@pytest.fixture(autouse=True)
def fresh_db():
    secure.init_db()
    secure._failed_attempts.clear()
    yield
    if os.path.exists(secure.DB_FILE):
        os.remove(secure.DB_FILE)


class TestRegistration:
    def test_valid_registration_succeeds(self):
        assert secure.register("bob", "correcthorsebattery", "bob@example.com") is True

    def test_duplicate_username_rejected(self):
        secure.register("bob", "correcthorsebattery", "bob@example.com")
        assert secure.register("bob", "differentpassword", "bob2@example.com") is False

    def test_invalid_username_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.register("b!", "correcthorsebattery", "bob@example.com")

    def test_invalid_email_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.register("bob", "correcthorsebattery", "not-an-email")

    def test_short_password_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.register("bob", "short", "bob@example.com")

    def test_password_is_not_stored_in_plaintext(self):
        secure.register("bob", "correcthorsebattery", "bob@example.com")
        import sqlite3
        conn = sqlite3.connect(secure.DB_FILE)
        row = conn.execute("SELECT password_hash FROM users WHERE username = 'bob'").fetchone()
        conn.close()
        assert row[0] != "correcthorsebattery"
        assert len(row[0]) == 64  # sha256 hex digest length from pbkdf2_hmac


class TestLogin:
    def test_correct_credentials_succeed(self):
        secure.register("bob", "correcthorsebattery", "bob@example.com")
        assert secure.login("bob", "correcthorsebattery") is True

    def test_wrong_password_fails(self):
        secure.register("bob", "correcthorsebattery", "bob@example.com")
        assert secure.login("bob", "wrongpassword") is False

    def test_nonexistent_user_fails(self):
        assert secure.login("nobody", "whatever") is False

    def test_sql_injection_payload_does_not_bypass_login(self):
        secure.register("bob", "correcthorsebattery", "bob@example.com")
        assert secure.login("bob' --", "anything") is False

    def test_account_locks_after_max_attempts(self):
        secure.register("bob", "correcthorsebattery", "bob@example.com")
        for _ in range(secure.MAX_ATTEMPTS):
            secure.login("bob", "wrongpassword")
        with pytest.raises(secure.ValidationError):
            secure.login("bob", "correcthorsebattery")  # locked out, even with the RIGHT password


class TestSearchUsers:
    def test_finds_matching_users(self):
        secure.register("alice", "correcthorsebattery", "alice@example.com")
        secure.register("bob", "correcthorsebattery", "bob@example.com")
        results = secure.search_users("ali")
        assert ("alice", "alice@example.com") in results

    def test_injection_payload_returns_no_extra_rows(self):
        secure.register("alice", "correcthorsebattery", "alice@example.com")
        results = secure.search_users("nonexistent' UNION SELECT username, password_hash FROM users --")
        assert results == []


class TestReadNotesFile:
    def test_reads_existing_file(self):
        content = secure.read_notes_file("welcome.txt")
        assert "Welcome" in content

    def test_traversal_payload_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.read_notes_file("../SECRET_marker_for_demo.txt")

    def test_nonexistent_file_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.read_notes_file("does_not_exist.txt")


class TestCalculate:
    def test_basic_arithmetic(self):
        assert secure.calculate("2 + 2") == 4
        assert secure.calculate("10 / 2") == 5
        assert secure.calculate("2 ** 8") == 256

    def test_code_execution_payload_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.calculate("__import__('os').system('echo pwned')")

    def test_name_lookup_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.calculate("open('/etc/passwd').read()")


class TestRunDiagnostic:
    def test_valid_hostname_accepted(self):
        # Should not raise, even if ping itself isn't installed in this sandbox
        secure.run_diagnostic("127.0.0.1")

    def test_injection_payload_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.run_diagnostic("127.0.0.1; echo pwned")

    def test_injection_with_pipe_rejected(self):
        with pytest.raises(secure.ValidationError):
            secure.run_diagnostic("127.0.0.1 | whoami")


class TestSafeHash:
    def test_sha256_used_not_md5(self):
        result = secure.safe_hash_for_export("test")
        assert len(result) == 64  # sha256 hex length (md5 would be 32)
