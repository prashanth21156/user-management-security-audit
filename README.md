# User Management CLI — Security Audit (Week 5)

A CLI user management application, audited and hardened against 9 real,
exploitable security vulnerabilities.

## Files

- `user_management_original.py` — the vulnerable baseline application
- `user_management_secure.py` — the hardened version (same functionality)
- `exploit_demos.py` — proof-of-concept exploits, run against the original (all succeed)
- `exploit_demos_retest.py` — the same exploits, run against the secure version (all blocked)
- `tests/test_secure_functionality.py` — 23 functional tests confirming no regressions
- `SECURITY_AUDIT.md` — the full audit report: methodology, findings, fixes, and verification
- `bandit_original.txt` / `bandit_secure.txt` — raw static analysis output, before and after
- `exploit_results_before.txt` / `exploit_results_after.txt` — raw exploit run output
- `notes/welcome.txt` — sample data for the notes-reading feature

## Running it

```bash
pip install -r requirements.txt

# See the vulnerabilities in action (harmless PoC payloads only)
python3 user_management_original.py
python3 exploit_demos.py

# See the same attacks fail against the hardened version
python3 user_management_secure.py
python3 exploit_demos_retest.py

# Confirm no legitimate functionality was broken
python3 -m pytest tests/ -v

# Re-run the static analysis yourself
pip install bandit
bandit user_management_original.py
bandit user_management_secure.py
```

## Result

9 vulnerabilities found (SQL injection x2, path traversal, command
injection, unsafe `eval()`, plaintext passwords, weak MD5, hardcoded
secret, information disclosure). All 9 fixed and verified: every exploit
that worked against the original fails against the secure version, and
23/23 functional tests confirm the app still works correctly. Full
details in `SECURITY_AUDIT.md`.
