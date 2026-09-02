"""Unit tests for regex rules and pattern matching."""

import unittest
from secrets_scanner.rules import get_default_rules
from secrets_scanner.models import RuleType


class TestRules(unittest.TestCase):

    def setUp(self):
        self.rules = {r.id: r for r in get_default_rules()}

    def test_aws_access_key_id(self):
        rule = self.rules["AWS_ACCESS_KEY_ID"]
        self.assertIsNotNone(rule.regex)
        
        # Valid AWS keys
        self.assertTrue(rule.regex.search("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(rule.regex.search("ASIA1234567890ABCDEF"))
        self.assertTrue(rule.regex.search("ABIA1234567890ABCDEF"))
        self.assertTrue(rule.regex.search("ACCA1234567890ABCDEF"))
        
        # Invalid / non-matching strings
        self.assertFalse(rule.regex.search("AKIA12345"))  # too short
        self.assertFalse(rule.regex.search("BKIAIOSFODNN7EXAMPLE"))  # wrong prefix
        self.assertFalse(rule.regex.search("akiaiosfodnn7example"))  # lowercase

    def test_aws_secret_access_key_context_aware(self):
        rule = self.rules["AWS_SECRET_ACCESS_KEY"]
        self.assertIsNotNone(rule.regex)
        
        # Matches when context keyword is present
        match1 = rule.regex.search('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
        self.assertIsNotNone(match1)
        self.assertEqual(match1.group(1), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        
        match2 = rule.regex.search('AWS_SECRET_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
        self.assertIsNotNone(match2)
        self.assertEqual(match2.group(1), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        
        # Does NOT match standalone 40-char string without AWS context
        self.assertFalse(rule.regex.search('commit_hash = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'))

    def test_github_tokens(self):
        rule = self.rules["GITHUB_TOKEN"]
        self.assertIsNotNone(rule.regex)
        
        # Matching
        self.assertTrue(rule.regex.search("ghp_" + "123456789012345678901234567890123456"))
        self.assertTrue(rule.regex.search("gho_123456789012345678901234567890123456"))
        self.assertTrue(rule.regex.search("ghu_123456789012345678901234567890123456"))
        self.assertTrue(rule.regex.search("ghs_123456789012345678901234567890123456"))
        self.assertTrue(rule.regex.search("ghr_123456789012345678901234567890123456"))
        
        # Fine-grained personal access token
        fine_grained = "github_pat_11AAAAAAA0123456789012_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567"
        self.assertTrue(rule.regex.search(fine_grained))
        
        # Non-matching
        self.assertFalse(rule.regex.search("ghp_short"))

    def test_stripe_keys(self):
        rule = self.rules["STRIPE_API_KEY"]
        self.assertIsNotNone(rule.regex)
        
        self.assertTrue(rule.regex.search("sk_" + "live_51Abcdefghijklmnopqrstuvwxyz123"))
        self.assertTrue(rule.regex.search("rk_" + "live_51Abcdefghijklmnopqrstuvwxyz123"))
        self.assertTrue(rule.regex.search("sk_test_51Abcdefghijklmnopqrstuvwxyz123"))
        
        self.assertFalse(rule.regex.search("sk_invalid_123"))

    def test_private_key_header(self):
        rule = self.rules["PRIVATE_KEY_HEADER"]
        self.assertIsNotNone(rule.regex)
        
        self.assertTrue(rule.regex.search("-----BEGIN RSA PRIVATE KEY-----"))
        self.assertTrue(rule.regex.search("-----BEGIN EC PRIVATE KEY-----"))
        self.assertTrue(rule.regex.search("-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertTrue(rule.regex.search("-----BEGIN PRIVATE KEY-----"))
        
        self.assertFalse(rule.regex.search("-----BEGIN PUBLIC KEY-----"))
        self.assertFalse(rule.regex.search("-----BEGIN CERTIFICATE-----"))

    def test_jwt_token(self):
        rule = self.rules["JWT_TOKEN"]
        self.assertIsNotNone(rule.regex)
        
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.assertTrue(rule.regex.search(jwt))
        self.assertFalse(rule.regex.search("not.a.valid.jwt"))

    def test_database_connection_string(self):
        rule = self.rules["DATABASE_CONNECTION_STRING"]
        self.assertIsNotNone(rule.regex)
        
        self.assertTrue(rule.regex.search("postgres://admin:secretpass123@db.prod.internal:5432/appdb"))
        self.assertTrue(rule.regex.search("mysql://user:pass@127.0.0.1:3306/test"))
        self.assertTrue(rule.regex.search("mongodb+srv://app_user:dbpassword@cluster0.mongodb.net/test"))
        
        # URI without credentials should not match
        self.assertFalse(rule.regex.search("https://example.com/api/v1/users"))

    def test_hardcoded_password(self):
        rule = self.rules["HARDCODED_PASSWORD"]
        self.assertIsNotNone(rule.regex)
        
        match = rule.regex.search('password = "SuperSecretPassword123!"')
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "SuperSecretPassword123!")
        
        match2 = rule.regex.search('db_pass: "MyDatabasePass99"')
        self.assertIsNotNone(match2)
        self.assertEqual(match2.group(1), "MyDatabasePass99")

    def test_generic_api_key(self):
        rule = self.rules["GENERIC_API_KEY"]
        self.assertIsNotNone(rule.regex)
        
        match = rule.regex.search('api_key = "dGVzdC1zZWNyZXQta2V5LXZhbHVlMTIzNDU="')
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "dGVzdC1zZWNyZXQta2V5LXZhbHVlMTIzNDU=")
        
        match2 = rule.regex.search('client_secret: "9f8e7d6c5b4a3210"')
        self.assertIsNotNone(match2)

        match3 = rule.regex.search('bearer_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"')
        self.assertIsNotNone(match3)

    def test_slack_tokens(self):
        rule = self.rules["SLACK_TOKEN"]
        self.assertIsNotNone(rule.regex)

        # Bot token
        self.assertTrue(rule.regex.search("xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx"))
        # User token
        self.assertTrue(rule.regex.search("xoxp-" + "123456789012-1234567890123-123456789012-abcdefghijklmnopqrstuvwx"))
        # App-level token
        self.assertTrue(rule.regex.search("xapp-1-" + "A0123456789-1234567890123-abcdefghijklmnopqrstuvwxyz0123456789"))

        # Non-matching strings
        self.assertFalse(rule.regex.search("xox-invalid-token"))
        self.assertFalse(rule.regex.search("slack_token_short"))

    def test_google_api_keys(self):
        rule = self.rules["GOOGLE_API_KEY"]
        self.assertIsNotNone(rule.regex)

        # Valid Google API Key (AIza + 35 characters = 39 chars total)
        key1 = "AIzaSyD-1234567890abcdefghijklmnopqrstu"
        key2 = "AIza" + "B" * 35
        self.assertEqual(len(key1), 39)
        self.assertEqual(len(key2), 39)
        self.assertTrue(rule.regex.search(key1))
        self.assertTrue(rule.regex.search(key2))

        # Non-matching
        self.assertFalse(rule.regex.search("AIzaSyShort"))  # too short
        self.assertFalse(rule.regex.search("BIza" + "B" * 35))  # wrong prefix

    def test_npm_tokens(self):
        rule = self.rules["NPM_TOKEN"]
        self.assertIsNotNone(rule.regex)

        # Valid npm access token (npm_ + 36 alphanumeric characters)
        token1 = "npm_" + "a" * 36
        token2 = "npm_9876543210abcdefghijklmnopqrstuvwxyz"
        self.assertEqual(len(token1), 40)
        self.assertEqual(len(token2), 40)
        self.assertTrue(rule.regex.search(token1))
        self.assertTrue(rule.regex.search(token2))

        # Non-matching
        self.assertFalse(rule.regex.search("npm_short"))
        self.assertFalse(rule.regex.search("pypi_" + "a" * 36))

    def test_pypi_tokens(self):
        rule = self.rules["PYPI_TOKEN"]
        self.assertIsNotNone(rule.regex)

        # Valid PyPI upload token (starts with pypi- and >= 50 characters)
        valid_pypi = "pypi-AgEIcHlwaS5vcmcCJDEyMzQ1NgA" + "A" * 60
        self.assertTrue(rule.regex.search(valid_pypi))

        # Negative test 1: Long base64 string (150 chars) that does NOT start with pypi-
        long_base64_blob = "AgEIcHlwaS5vcmcCJDEyMzQ1Ng" + "B" * 120
        self.assertFalse(rule.regex.search(long_base64_blob))

        # Negative test 2: Token starting with pypi- but too short (< 50 chars)
        self.assertFalse(rule.regex.search("pypi-short-dummy-token"))

        # Negative test 3: Different prefix with pypi in middle
        self.assertFalse(rule.regex.search("mypypi-AgEIcHlwaS5vcmcCJDEyMzQ1NgA" + "A" * 60))

    def test_twilio_keys(self):
        rule = self.rules["TWILIO_KEY"]
        self.assertIsNotNone(rule.regex)

        # Twilio API Key (SK + 32 hex chars)
        self.assertTrue(rule.regex.search("SK" + "0123456789abcdef0123456789abcdef"))
        # Twilio Account SID (AC + 32 hex chars)
        self.assertTrue(rule.regex.search("AC" + "0123456789abcdef0123456789abcdef"))

        # Non-matching
        self.assertFalse(rule.regex.search("SK012345"))  # too short
        self.assertFalse(rule.regex.search("ZZ0123456789abcdef0123456789abcdef"))  # wrong prefix

    def test_ssh_private_key(self):
        rule = self.rules["SSH_PRIVATE_KEY"]
        self.assertIsNotNone(rule.regex)

        # OpenSSH private key header
        self.assertTrue(rule.regex.search("-----BEGIN OPENSSH PRIVATE KEY-----"))
        # PuTTY private key header
        self.assertTrue(rule.regex.search("PuTTY-User-Key-File-2: ssh-rsa"))
        self.assertTrue(rule.regex.search("PuTTY-User-Key-File-3: ssh-ed25519"))

        # Non-matching
        self.assertFalse(rule.regex.search("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@host"))
        self.assertFalse(rule.regex.search("-----BEGIN PUBLIC KEY-----"))

    def test_generic_secret_assignment(self):
        rule = self.rules["GENERIC_SECRET_ASSIGNMENT"]
        self.assertIsNotNone(rule.regex)

        # password =
        match1 = rule.regex.search('password = "production_super_secret_999"')
        self.assertIsNotNone(match1)
        self.assertEqual(match1.group(1), "production_super_secret_999")

        # secret =
        match2 = rule.regex.search('secret = "backend_app_signing_secret_xyz"')
        self.assertIsNotNone(match2)
        self.assertEqual(match2.group(1), "backend_app_signing_secret_xyz")

        # api_key =
        match3 = rule.regex.search('api_key="service_custom_token_12345"')
        self.assertIsNotNone(match3)
        self.assertEqual(match3.group(1), "service_custom_token_12345")

        # Unquoted assignment
        match4 = rule.regex.search('api_key=my_custom_secret_key_8888')
        self.assertIsNotNone(match4)
        self.assertEqual(match4.group(1), "my_custom_secret_key_8888")

        # Too short (< 8 chars)
        self.assertFalse(rule.regex.search('secret = "short"'))

    def test_placeholder_value_detection(self):
        from secrets_scanner.rules import is_placeholder_value
        
        # Obvious placeholder values must return True
        self.assertTrue(is_placeholder_value("changeme"))
        self.assertTrue(is_placeholder_value("your_api_key_here"))
        self.assertTrue(is_placeholder_value("YOUR_SECRET_KEY"))
        self.assertTrue(is_placeholder_value("insert_token_here"))
        self.assertTrue(is_placeholder_value("<API_KEY>"))
        self.assertTrue(is_placeholder_value("${SECRET_TOKEN}"))
        self.assertTrue(is_placeholder_value("xxxxxxxxxxxxxxxx"))
        self.assertTrue(is_placeholder_value("****************"))

        # Explicitly required placeholder strings
        self.assertTrue(is_placeholder_value("xxx"))
        self.assertTrue(is_placeholder_value("xxxx"))
        self.assertTrue(is_placeholder_value("<REDACTED>"))
        self.assertTrue(is_placeholder_value("[REDACTED]"))
        self.assertTrue(is_placeholder_value("{REDACTED}"))
        self.assertTrue(is_placeholder_value("redacted"))
        self.assertTrue(is_placeholder_value("REDACTED"))

        # Real secret values must return False
        self.assertFalse(is_placeholder_value("AKIAIOSFODNN7EXAMPLE"))
        self.assertFalse(is_placeholder_value("c8F9zLm2vQ7xP4wK1jR6tN8bY3sA5eD0"))
        self.assertFalse(is_placeholder_value("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
        self.assertFalse(is_placeholder_value("production_super_secret_999"))


if __name__ == "__main__":
    unittest.main()


