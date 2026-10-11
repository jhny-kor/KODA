"""Focused public-scan checks for native archive extraction limits."""

import gzip
import json
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from io import BytesIO
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "app/KODA/KODA/NativeSecurityScanner.swift"
MAX_INPUT = 256 * 1024 * 1024


class NativeArchiveLimitsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="koda-native-archive-tests-")
        cls.root = Path(cls.workspace.name)
        harness = cls.root / "ArchiveHarness.swift"
        harness.write_text(
            """
import Foundation
enum AppLanguage: String { case ko, en }
enum KodaRuleSettings { static func disabledIDs() -> Set<String> { [] } }
@main struct ArchiveHarness {
    static func main() throws {
        let result = try NativeSecurityScanner().scan(targets: [URL(fileURLWithPath: CommandLine.arguments[1])])
        let value: [String: Any] = ["files": result.scannedFileCount, "warnings": result.warnings]
        let encoded = try JSONSerialization.data(withJSONObject: value)
        print(String(data: encoded, encoding: .utf8)!)
    }
}
""",
            encoding="utf-8",
        )
        cls.binary = cls.root / "archive-harness"
        subprocess.run(["swiftc", str(SOURCE), str(harness), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def scan(self, archive: Path) -> dict:
        process = subprocess.run([str(self.binary), str(archive)], check=True, capture_output=True, text=True)
        return json.loads(process.stdout)

    def test_valid_zip_tar_and_gzip_still_scan(self):
        source = b"print('ok')\n"
        stored = self.root / "valid-stored.zip"
        deflated = self.root / "valid-deflated.zip"
        for path, compression in ((stored, zipfile.ZIP_STORED), (deflated, zipfile.ZIP_DEFLATED)):
            with zipfile.ZipFile(path, "w", compression=compression) as archive:
                archive.writestr("hello.py", source)
            self.assertEqual(self.scan(path)["files"], 1)

        tar_path = self.root / "valid.tar"
        with tarfile.open(tar_path, "w") as archive:
            info = tarfile.TarInfo("hello.py")
            info.size = len(source)
            archive.addfile(info, BytesIO(source))
        self.assertEqual(self.scan(tar_path)["files"], 1)

        tar_gzip_path = self.root / "valid.tar.gz"
        tar_gzip_path.write_bytes(gzip.compress(tar_path.read_bytes()))
        self.assertEqual(self.scan(tar_gzip_path)["files"], 1)

        gzip_path = self.root / "hello.py.gz"
        gzip_path.write_bytes(gzip.compress(source))
        self.assertEqual(self.scan(gzip_path)["files"], 1)

    def test_empty_deflated_member_does_not_skip_other_files(self):
        for level in (0, 6, 9):
            with self.subTest(compression_level=level):
                archive = self.root / f"empty-{level}.zip"
                with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED,
                                     compresslevel=level) as output:
                    output.writestr("empty.py", b"")
                    output.writestr("hello.py", b"print('ok')\n")
                result = self.scan(archive)
                self.assertEqual(result["files"], 2)
                self.assertEqual(result["warnings"], [])

        empty_gzip = self.root / "empty.py.gz"
        empty_gzip.write_bytes(gzip.compress(b""))
        self.assertEqual(self.scan(empty_gzip)["files"], 1)

    def test_empty_deflate_requires_a_complete_valid_stream(self):
        # Raw DEFLATE of an empty file is 03 00; a zero size alone proves nothing.
        for payload in (b"", b"\x03", b"\x07\x00", b"\x03\x00garbage"):
            with self.subTest(payload=payload):
                archive = self.root / "malformed-empty.zip"
                name = b"empty.py"
                header = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0,
                                     0, len(payload), 0, len(name), 0)
                archive.write_bytes(header + name + payload)
                result = self.scan(archive)
                self.assertEqual(result["files"], 0)
                self.assertTrue(result["warnings"])

    def test_deflate_multiple_output_chunks_and_truncation(self):
        source = b"#" + b"a" * 150_000 + b"\n"
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(source) + compressor.flush()
        name = b"large.py"
        for payload, valid in ((compressed, True), (compressed[:-1], False),
                               (compressed + b"garbage", False)):
            with self.subTest(valid=valid, size=len(payload)):
                archive = self.root / "large.zip"
                header = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0,
                                     zlib.crc32(source), len(payload), len(source), len(name), 0)
                archive.write_bytes(header + name + payload)
                result = self.scan(archive)
                self.assertEqual(result["files"], 1 if valid else 0)
                self.assertEqual(bool(result["warnings"]), not valid)

    def test_negative_tar_size_is_rejected_without_crash(self):
        tar_path = self.root / "negative.tar"
        header = bytearray(512)
        header[:8] = b"hello.py"
        header[124:136] = b"-0000000001\0"
        tar_path.write_bytes(header + bytearray(1024))
        result = self.scan(tar_path)
        self.assertEqual(result["files"], 0)
        self.assertTrue(any("tar size" in item for item in result["warnings"]))

        header[124:136] = b"not-octal\0\0\0"
        tar_path.write_bytes(header + bytearray(1024))
        self.assertTrue(any("tar size" in item for item in self.scan(tar_path)["warnings"]))

    def test_declared_zip_expansion_over_limit_is_rejected(self):
        archive = self.root / "oversized-member.zip"
        name = b"hello.py"
        header = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, 0, 1, MAX_INPUT + 1, len(name), 0)
        archive.write_bytes(header + name + b"x")
        result = self.scan(archive)
        self.assertEqual(result["files"], 0)
        self.assertTrue(any("한도를 초과" in item for item in result["warnings"]))

    def test_oversized_input_and_nested_archive_depth_are_rejected(self):
        oversized = self.root / "oversized-input.zip"
        with oversized.open("wb") as output:
            output.truncate(MAX_INPUT + 1)
        self.assertTrue(any("한도를 초과" in item for item in self.scan(oversized)["warnings"]))

        def nested_payload(depth):
            payload = b"print('ok')\n"
            for level in range(depth, 0, -1):
                buffer = BytesIO()
                with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
                    archive.writestr("child.zip" if level < depth else "hello.py", payload)
                payload = buffer.getvalue()
            return payload

        allowed = self.root / "allowed-nested.zip"
        allowed.write_bytes(nested_payload(5))
        self.assertEqual(self.scan(allowed)["files"], 1)

        nested = self.root / "nested.zip"
        nested.write_bytes(nested_payload(6))
        result = self.scan(nested)
        self.assertEqual(result["files"], 0)
        self.assertTrue(any("한도를 초과" in item for item in result["warnings"]))

    def test_gzip_trailer_understates_output(self):
        archive = self.root / "wrong-size.py.gz"
        raw = bytearray(gzip.compress(b"print('ok')\n"))
        raw[-4:] = struct.pack("<I", 1)
        archive.write_bytes(raw)
        result = self.scan(archive)
        self.assertEqual(result["files"], 0)
        self.assertTrue(any("압축파일을 읽을 수 없습니다" in item for item in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
