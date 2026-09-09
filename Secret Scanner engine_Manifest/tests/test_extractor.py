"""Unit tests for safe archive extraction and bomb / traversal protections."""

import io
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile

from secrets_scanner.extractor import ArchiveSecurityError, safe_extract_archive


class TestSafeExtractor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_safe_zip_extraction(self):
        zip_path = os.path.join(self.temp_dir, "good.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("app/main.py", 'print("hello world")')
            zf.writestr("app/config.json", '{"key": "value"}')

        dest_dir = os.path.join(self.temp_dir, "extracted_good")
        out_dir = safe_extract_archive(zip_path, dest_dir)
        self.assertEqual(out_dir, os.path.abspath(dest_dir))
        self.assertTrue(os.path.exists(os.path.join(dest_dir, "app", "main.py")))

    def test_safe_tar_extraction(self):
        tar_path = os.path.join(self.temp_dir, "good.tar.gz")
        with tarfile.open(tar_path, "w:gz") as tf:
            content = b'print("tar hello")'
            ti = tarfile.TarInfo(name="pkg/script.py")
            ti.size = len(content)
            tf.addfile(ti, io.BytesIO(content))

        dest_dir = os.path.join(self.temp_dir, "extracted_tar")
        out_dir = safe_extract_archive(tar_path, dest_dir)
        self.assertTrue(os.path.exists(os.path.join(dest_dir, "pkg", "script.py")))

    def test_zip_slip_path_traversal_rejected_and_cleaned(self):
        zip_path = os.path.join(self.temp_dir, "malicious.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../escape.txt", "pwned")

        dest_dir = os.path.join(self.temp_dir, "extracted_malicious")
        with self.assertRaises(ArchiveSecurityError):
            safe_extract_archive(zip_path, dest_dir)

        # Ensure destination directory is cleaned up on failure
        self.assertFalse(os.path.exists(dest_dir))

    def test_incremental_zip_bomb_size_exceeded_and_cleaned(self):
        zip_path = os.path.join(self.temp_dir, "bomb.zip")
        # Create a compressed file of 1MB (compressible from 1MB zeros)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bigfile.txt", b"\x00" * (1024 * 1024))

        dest_dir = os.path.join(self.temp_dir, "extracted_bomb")
        # Limit total uncompressed bytes to 500 KB
        with self.assertRaises(ArchiveSecurityError):
            safe_extract_archive(zip_path, dest_dir, max_total_bytes=500 * 1024)

        # Ensure directory is cleaned up on failure
        self.assertFalse(os.path.exists(dest_dir))

    def test_tar_symlink_rejected(self):
        tar_path = os.path.join(self.temp_dir, "symlink_evil.tar")
        with tarfile.open(tar_path, "w") as tf:
            ti = tarfile.TarInfo(name="evil_link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tf.addfile(ti)

        dest_dir = os.path.join(self.temp_dir, "extracted_symlink")
        with self.assertRaises(ArchiveSecurityError):
            safe_extract_archive(tar_path, dest_dir)
        self.assertFalse(os.path.exists(dest_dir))

    def test_tar_hardlink_rejected(self):
        tar_path = os.path.join(self.temp_dir, "hardlink_evil.tar")
        with tarfile.open(tar_path, "w") as tf:
            ti = tarfile.TarInfo(name="evil_hardlink")
            ti.type = tarfile.LNKTYPE
            ti.linkname = "/etc/shadow"
            tf.addfile(ti)

        dest_dir = os.path.join(self.temp_dir, "extracted_hardlink")
        with self.assertRaises(ArchiveSecurityError):
            safe_extract_archive(tar_path, dest_dir)
        self.assertFalse(os.path.exists(dest_dir))

    def test_max_files_exceeded(self):
        zip_path = os.path.join(self.temp_dir, "many_files.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(10):
                zf.writestr(f"file_{i}.txt", "data")

        dest_dir = os.path.join(self.temp_dir, "extracted_many")
        with self.assertRaises(ArchiveSecurityError):
            safe_extract_archive(zip_path, dest_dir, max_total_files=5)

        self.assertFalse(os.path.exists(dest_dir))


if __name__ == "__main__":
    unittest.main()

