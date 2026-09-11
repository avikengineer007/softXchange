"""Unit tests for safe filesystem traversal and budget controls."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from secrets_scanner.walker import (
    ScanBudgetExceeded,
    is_binary_content,
    read_text_file,
    walk_directory,
)


class TestWalker(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_binary_detection(self):
        bin_data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00"
        is_bin, encoding = is_binary_content(bin_data)
        self.assertTrue(is_bin)
        self.assertEqual(encoding, "binary")

        text_data = b"def hello():\n    return 'world'\n"
        is_bin, encoding = is_binary_content(text_data)
        self.assertFalse(is_bin)
        self.assertEqual(encoding, "utf-8")

    def test_utf16_bom_detection(self):
        utf16_data = "hello world".encode("utf-16")
        is_bin, encoding = is_binary_content(utf16_data)
        self.assertFalse(is_bin)
        self.assertEqual(encoding, "utf-16")

    def test_latin1_fallback(self):
        latin1_bytes = "café = 100".encode("latin-1")
        file_path = os.path.join(self.test_dir, "latin1.txt")
        with open(file_path, "wb") as f:
            f.write(latin1_bytes)
            
        success, content, encoding, byte_count = read_text_file(file_path)
        self.assertTrue(success)
        self.assertIn("café", content)

    def test_skips_ignored_directories(self):
        # Create node_modules and .git folders
        nm_dir = os.path.join(self.test_dir, "node_modules")
        git_dir = os.path.join(self.test_dir, ".git")
        os.makedirs(nm_dir)
        os.makedirs(git_dir)

        with open(os.path.join(nm_dir, "package.json"), "w") as f:
            f.write('{"name": "test"}')
        with open(os.path.join(git_dir, "config"), "w") as f:
            f.write('[core]')

        # Normal file
        with open(os.path.join(self.test_dir, "app.py"), "w") as f:
            f.write('print("hello")')

        walker = walk_directory(self.test_dir)
        files = []
        try:
            while True:
                path, content = next(walker)
                files.append(os.path.basename(path))
        except StopIteration as e:
            skipped = e.value

        self.assertEqual(files, ["app.py"])
        skipped_reasons = [s.reason for s in skipped]
        self.assertEqual(skipped_reasons.count("ignored_directory"), 2)

    def test_skips_oversized_file(self):
        large_file = os.path.join(self.test_dir, "large.txt")
        with open(large_file, "wb") as f:
            f.write(b"x" * 200)

        # Set max_file_size to 100 bytes
        walker = walk_directory(self.test_dir, max_file_size=100)
        files = []
        try:
            while True:
                path, content = next(walker)
                files.append(path)
        except StopIteration as e:
            skipped = e.value

        self.assertEqual(len(files), 0)
        self.assertEqual(len(skipped), 1)
        self.assertTrue(skipped[0].reason.startswith("size_limit_exceeded"))

    def test_directory_depth_limit_budget_exceeded(self):
        # Create deep directory nesting
        nested = self.test_dir
        for i in range(5):
            nested = os.path.join(nested, f"dir_{i}")
        os.makedirs(nested)
        with open(os.path.join(nested, "deep.txt"), "w") as f:
            f.write("deep file")

        # Walk with max_depth=3
        walker = walk_directory(self.test_dir, max_depth=3)
        with self.assertRaises(ScanBudgetExceeded):
            try:
                while True:
                    next(walker)
            except StopIteration:
                pass

    def test_file_count_budget_exceeded(self):
        # Create 10 files
        for i in range(10):
            with open(os.path.join(self.test_dir, f"file_{i}.txt"), "w") as f:
                f.write("content")

        # Walk with max_total_files=5
        walker = walk_directory(self.test_dir, max_total_files=5)
        with self.assertRaises(ScanBudgetExceeded):
            try:
                while True:
                    next(walker)
            except StopIteration:
                pass


if __name__ == "__main__":
    unittest.main()
