"""Unit tests for Shannon entropy scoring and candidate extraction."""

import unittest
from secrets_scanner.entropy import (
    calculate_shannon_entropy,
    detect_charset,
    extract_entropy_candidates,
    is_high_entropy_token,
)


class TestEntropy(unittest.TestCase):

    def test_entropy_homogeneous_string(self):
        # All same characters should have 0 entropy
        self.assertEqual(calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaa"), 0.0)

    def test_detect_charset(self):
        self.assertEqual(detect_charset("0123456789abcdefABCDEF"), "hex")
        self.assertEqual(detect_charset("aB3+d/E=="), "base64")
        self.assertEqual(detect_charset("hello world! @#$"), "general")

    def test_hex_entropy_scoring(self):
        # 40-char random hex string
        hex_token = "4a8f9c2d1e7b6a50f3e2d1c0b9a876543210fedc"
        is_high, score, charset = is_high_entropy_token(hex_token, min_length=20)
        self.assertEqual(charset, "hex")
        self.assertGreaterEqual(score, 3.0)
        self.assertTrue(is_high)

    def test_base64_entropy_scoring(self):
        # High entropy base64 token
        base64_token = "c8F9zLm2vQ7xP4wK1jR6tN8bY3sA5eD0"
        is_high, score, charset = is_high_entropy_token(base64_token, min_length=20)
        self.assertEqual(charset, "base64")
        self.assertGreaterEqual(score, 4.5)
        self.assertTrue(is_high)

    def test_low_entropy_repetitive_string_not_flagged(self):
        token = "abcabcabcabcabcabcabcabc"
        is_high, score, charset = is_high_entropy_token(token, min_length=20)
        self.assertFalse(is_high)

    def test_short_token_not_flagged(self):
        short_token = "aB3dE7x"
        is_high, score, charset = is_high_entropy_token(short_token, min_length=20)
        self.assertFalse(is_high)
        self.assertEqual(charset, "short")

    def test_extract_entropy_candidates(self):
        line = 'const token = "c8F9zLm2vQ7xP4wK1jR6tN8bY3sA5eD0"; let other = 123;'
        candidates = extract_entropy_candidates(line, min_length=20)
        self.assertEqual(len(candidates), 1)
        token_val, start, end = candidates[0]
        self.assertEqual(token_val, "c8F9zLm2vQ7xP4wK1jR6tN8bY3sA5eD0")
        self.assertEqual(line[start:end], "c8F9zLm2vQ7xP4wK1jR6tN8bY3sA5eD0")


if __name__ == "__main__":
    unittest.main()
