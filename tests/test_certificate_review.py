from __future__ import annotations

import base64
import hashlib
import shutil
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from security_scanner import certificate_review as review


_PEM = b"""-----BEGIN CERTIFICATE-----
MIIBKDCBzgIJAPeCfR53Lnz3MAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEWtvZGEt
dGVzdC5pbnZhbGlkMB4XDTI2MTEyMzExNDYzOFoXDTI2MTEyOTExNDYzOFowHDEa
MBgGA1UEAwwRa29kYS10ZXN0LmludmFsaWQwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARx0KxR26oZ7iGL2h9sJlHeHhzd24lwLGVmBPRkcKk6B0jvZxItNVT1aKco
oMagts1WR5leNEK+A4A01TMSQiXdMAoGCCqGSM49BAMCA0kAMEYCIQCWT4DCWBPG
3Ye61m/gcewoKSEHfuezFyVBgp+3/yO7vQIhANTIFpd9eOKCJw30g4m8QCsaeoPc
m87/gtfUIVmhMfqg
-----END CERTIFICATE-----
"""
_DER = base64.b64decode(b"".join(_PEM.splitlines()[1:-1]))


class CertificateReviewTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32" or shutil.which("openssl"), "OS certificate parser unavailable")
    def test_pem_and_der_use_same_certificate_and_report_date_status(self) -> None:
        for payload, input_format, day, state in (
            (_PEM, "PEM", 22, "NOT_YET_VALID"),
            (_DER, "DER", 23, "VALID"),
            (_PEM, "PEM", 30, "EXPIRED"),
        ):
            with self.subTest(input_format=input_format, state=state):
                data = review.review_certificate(payload, now=datetime(2026, 11, day, 12, tzinfo=timezone.utc))
                self.assertEqual(data["input_format"], input_format)
                self.assertEqual(data["validity"], state)
                self.assertEqual(data["sha256"], hashlib.sha256(_DER).hexdigest())
                self.assertEqual(data["not_before"], "2026-11-23T11:46:38Z")
                self.assertEqual(data["not_after"], "2026-11-29T11:46:38Z")
                self.assertEqual(data["signature_oid"], "1.2.840.10045.4.3.2")
                self.assertFalse(data["weak_signature"])

    def test_rejects_truncated_der_and_mixed_pem_before_os_parser(self) -> None:
        private_key = b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----"
        with patch.object(review, "_certificate_validity", side_effect=AssertionError("OS parser called")):
            for payload in (_DER[:-1], _DER + _DER, _PEM + _PEM, _PEM + private_key, b"",
                            b"x" * (review.MAX_CERTIFICATE_BYTES + 1)):
                with self.assertRaises(ValueError):
                    review.review_certificate(payload)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is optional")
    def test_powershell_backend_reads_utc_dates_from_der(self) -> None:
        valid_from, expires_at = review._windows_validity(_DER, shutil.which("pwsh"))
        self.assertEqual(valid_from, datetime(2026, 11, 23, 11, 46, 38, tzinfo=timezone.utc))
        self.assertEqual(expires_at, datetime(2026, 11, 29, 11, 46, 38, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
