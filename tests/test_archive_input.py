import io
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from security_scanner.archive_input import prepare_input_target
from security_scanner.config import ConfigError


class ArchiveInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "source.zip"
        self.work = self.root / "work"

    def zip_bytes(self, *, compression=zipfile.ZIP_DEFLATED, name="src/app.py"):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            archive.writestr(name, "print('hello')\n")
        return output.getvalue()

    def extract(self, **limits):
        return prepare_input_target(self.path, self.work, **limits)

    def test_normal_zip_compression_methods(self):
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                            zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.subTest(compression=compression):
                self.path.write_bytes(self.zip_bytes(compression=compression))
                target = self.extract()
                self.assertEqual((target / "src/app.py").read_text(), "print('hello')\n")

    def test_zip64_and_maximum_comment(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            with archive.open("src/app.py", "w", force_zip64=True) as member:
                member.write(b"print('hello')\n")
            archive.comment = b"x" * 65535
        self.assertEqual((self.extract() / "src/app.py").read_bytes(), b"print('hello')\n")

    def test_valid_empty_zip(self):
        with zipfile.ZipFile(self.path, "w"):
            pass
        self.assertEqual(list(self.extract().iterdir()), [])

    def test_empty_upload_is_reported_as_empty(self):
        self.path.write_bytes(b"")
        with self.assertRaisesRegex(ConfigError, "Archive input is empty"):
            self.extract()

    def test_truncated_zip_is_not_reported_as_unsupported_format(self):
        self.path.write_bytes(self.zip_bytes()[:-22])
        with self.assertRaisesRegex(ConfigError, "Invalid or incomplete ZIP archive"):
            self.extract()

    def test_non_zip_content_with_zip_extension(self):
        self.path.write_bytes(b"this is not a ZIP file")
        with self.assertRaisesRegex(ConfigError, "Invalid or incomplete ZIP archive"):
            self.extract()

    def test_encrypted_member_has_specific_error(self):
        data = bytearray(self.zip_bytes())
        for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            offset = data.index(signature) + flag_offset
            flags = struct.unpack_from("<H", data, offset)[0]
            struct.pack_into("<H", data, offset, flags | 1)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ConfigError, "Encrypted ZIP member.*src/app.py"):
            self.extract()

    def test_unsupported_member_compression_has_specific_error(self):
        data = bytearray(self.zip_bytes())
        for signature, method_offset in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
            struct.pack_into("<H", data, data.index(signature) + method_offset, 99)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ConfigError, "Unsupported ZIP compression method 99.*src/app.py"):
            self.extract()

    def test_corrupt_member_is_rejected(self):
        data = bytearray(self.zip_bytes(compression=zipfile.ZIP_STORED))
        data[data.index(b"print")] ^= 1
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ConfigError, "Could not extract archive.*CRC"):
            self.extract()

    def test_path_traversal_is_rejected(self):
        self.path.write_bytes(self.zip_bytes(name="../escape.py"))
        with self.assertRaisesRegex(ConfigError, "unsafe path"):
            self.extract()
        self.assertFalse((self.root / "escape.py").exists())

    def test_extraction_limits_are_preserved(self):
        self.path.write_bytes(self.zip_bytes())
        with self.assertRaisesRegex(ConfigError, "expands beyond"):
            self.extract(max_bytes=1)
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("one.py", "one")
            archive.writestr("two.py", "two")
        with self.assertRaisesRegex(ConfigError, "more than 1 files"):
            self.extract(max_files=1)

    def test_content_detection_preserves_tar_with_zip_extension(self):
        with tarfile.open(self.path, "w") as archive:
            member = tarfile.TarInfo("src/app.py")
            member.size = 3
            archive.addfile(member, io.BytesIO(b"one"))
        self.assertEqual((self.extract() / "src/app.py").read_bytes(), b"one")
