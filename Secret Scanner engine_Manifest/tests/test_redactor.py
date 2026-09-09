"""Unit tests for redaction and snippet formatting."""

import unittest
from secrets_scanner.redactor import redact_line_snippet, redact_secret


class TestRedactor(unittest.TestCase):
    
    def test_redact_long_secret(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = redact_secret(secret)
        self.assertEqual(len(redacted), len(secret))
        self.assertTrue(redacted.startswith("AKIA"))
        self.assertTrue(redacted.endswith("MPLE"))
        self.assertEqual(redacted[4:-4], "*" * (len(secret) - 8))
        self.assertNotIn("IOSFODNN7EXA", redacted)

    def test_redact_short_secret(self):
        secret = "123456"
        redacted = redact_secret(secret)
        self.assertEqual(redacted, "********")
        self.assertNotIn("123456", redacted)

    def test_redact_exact_eight_chars(self):
        secret = "12345678"
        redacted = redact_secret(secret)
        self.assertEqual(redacted, "********")
        self.assertNotIn("12345678", redacted)

    def test_redact_empty_secret(self):
        self.assertEqual(redact_secret(""), "")

    def test_redact_line_snippet(self):
        line = 'export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE" # prod key'
        start = line.index("AKIAIOSFODNN7EXAMPLE")
        end = start + len("AKIAIOSFODNN7EXAMPLE")
        
        snippet = redact_line_snippet(line, start, end)
        self.assertIn("AKIA", snippet)
        self.assertIn("MPLE", snippet)
        self.assertIn("export AWS_ACCESS_KEY_ID=", snippet)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", snippet)


if __name__ == "__main__":
    unittest.main()
