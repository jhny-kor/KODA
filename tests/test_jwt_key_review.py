import base64
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest import TestCase
from unittest.mock import patch

from security_scanner.cli import main
from security_scanner.jwt_key_review import key_bit_length, review_jwt_key


class JwtKeyReviewTests(TestCase):
    def test_algorithm_boundaries_at_actual_key_sizes(self):
        for algorithm, bits in (("HS256", 256), ("HS384", 384), ("HS512", 512)):
            with self.subTest(algorithm=algorithm):
                self.assertEqual(review_jwt_key(algorithm, bits - 8)["status"], "TOO_SHORT")
                self.assertEqual(review_jwt_key(algorithm, bits)["status"], "MEETS_MINIMUM_LENGTH")

    def test_encoded_environment_key_length_without_submitting_or_outputting_key(self):
        key = base64.urlsafe_b64encode(bytes(range(192, 216))).decode("ascii").rstrip("=")
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict("os.environ", {"LOCAL_TEST_JWT_KEY": key}), redirect_stdout(output), redirect_stderr(errors):
            exit_code = main(["jwt-key-review", "--algorithm", "HS256", "--key-env", "LOCAL_TEST_JWT_KEY",
                              "--key-encoding", "base64url"])
        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(output.getvalue())["key_bits"], 192)
        self.assertNotIn(key, output.getvalue() + errors.getvalue())

    def test_utf8_length_and_invalid_base64(self):
        self.assertEqual(key_bit_length("한글", "utf8"), 48)
        self.assertEqual(key_bit_length("YQ==", "base64"), 8)
        for value in ("YQ=", "YR==", "+/a_", "x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                key_bit_length(value, "base64url")
