import unittest
import db
from app import app, PEPPER

class TestSecureLoginSystem(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def test_01_inspect_db(self):
        """Verify inspect-db displays stored hashes without plain text."""
        response = self.client.get("/inspect-db")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"$2b$12$", response.data)
        self.assertIn(b"alice", response.data)
        print("[OK] test_01_inspect_db passed: Passwords shown as bcrypt $2b$12$ hashes.")

    def test_02_password_policy_enforcement(self):
        """Test registration rejects weak passwords."""
        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "test-token"

        weak_passwords = [
            "short",              # too short
            "alllowercase123!",   # no uppercase
            "ALLUPPERCASE123!",   # no lowercase
            "NoDigitsHere!abc",   # no digits
            "NoSpecialChars123",  # no special characters
        ]
        for weak_pw in weak_passwords:
            res = self.client.post("/register", data={
                "csrf_token": "test-token",
                "username": "weak_tester",
                "password": weak_pw,
                "confirm_password": weak_pw
            }, follow_redirects=True)
            self.assertIn(b"Password must", res.data)
        print("[OK] test_02_password_policy_enforcement passed: All weak passwords rejected.")

    def test_03_successful_registration_and_login(self):
        """Test successful registration and authenticated dashboard access."""
        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "test-token"

        import time
        test_user = f"user_{int(time.time())}"

        # Register dynamic user
        res_reg = self.client.post("/register", data={
            "csrf_token": "test-token",
            "username": test_user,
            "password": "StrongPassword@2026",
            "confirm_password": "StrongPassword@2026"
        }, follow_redirects=True)
        self.assertEqual(res_reg.status_code, 200)
        self.assertIn(b"Registration successful", res_reg.data)

        # Log in with the registered user
        res_login = self.client.post("/login", data={
            "csrf_token": "test-token",
            "username": test_user,
            "password": "StrongPassword@2026"
        }, follow_redirects=True)
        self.assertEqual(res_login.status_code, 200)
        self.assertIn(b"Authentication Successful", res_login.data)
        self.assertIn(test_user.encode("utf-8"), res_login.data)
        print("[OK] test_03_successful_registration_and_login passed: Registered & logged in.")

    def test_04_wrong_password_and_lockout(self):
        """Test repeated wrong passwords leading to account lockout."""
        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "test-token"

        # Try 4 wrong passwords
        for i in range(1, 5):
            res = self.client.post("/login", data={
                "csrf_token": "test-token",
                "username": "alice",
                "password": "WrongPassword!999"
            }, follow_redirects=True)
            self.assertIn(b"attempt(s) remaining", res.data)

        # 5th wrong password should trigger lockout
        res_lockout = self.client.post("/login", data={
            "csrf_token": "test-token",
            "username": "alice",
            "password": "WrongPassword!999"
        }, follow_redirects=True)
        self.assertIn(b"locked", res_lockout.data)
        print("[OK] test_04_wrong_password_and_lockout passed: Account successfully locked after 5 failures.")

        # Unlock alice for future tests
        db.reset_failed_attempts("alice")

    def test_05_sql_injection_rejection(self):
        """Verify SQL injection payload in login is rejected."""
        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "test-token"

        res = self.client.post("/login", data={
            "csrf_token": "test-token",
            "username": "' OR 1=1 --",
            "password": "' OR 1=1 --"
        }, follow_redirects=True)
        self.assertIn(b"Invalid username or password", res.data)
        print("[OK] test_05_sql_injection_rejection passed: SQLi payload treated as literal invalid user.")


if __name__ == "__main__":
    unittest.main()
