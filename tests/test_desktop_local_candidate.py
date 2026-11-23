import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from security_scanner.ai import local_candidate as local


ORIGINAL = "import pickle\ndef parse(value):\n    return pickle.loads(value)\n"
CANDIDATE = "import json\ndef parse(value):\n    return json.loads(value)\n"


class LocalCandidateTests(unittest.TestCase):
    def test_snapshot_is_rescanned_and_model_output_is_never_executed(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "side-effect"
            candidate = CANDIDATE + f"open({str(marker)!r}, 'w').close()\n"

            def respond(base, key, route, payload):
                proposal = {"source": candidate, "impact": "Accepts JSON", "tests": "Check invalid JSON"}
                return {"choices": [{"message": {"content": json.dumps(proposal)}}]}

            data = {"action": "inspect", "source": ORIGINAL, "name": "sample.py"}
            rule = local.process(data)["findings"][0]["rule"]
            result = local.process(dict(data, action="propose", model="test", rule=rule), respond)
            self.assertEqual(result["source"], candidate)
            self.assertFalse(marker.exists())
            self.assertIn("+import json", result["diff"])
            self.assertEqual(result["attempts"], 1)

    def test_repeat_and_changed_signature_do_not_pass(self):
        def respond(*args):
            proposal = {"source": CANDIDATE.replace("value", "changed"), "impact": "impact", "tests": "tests"}
            return {"choices": [{"message": {"content": json.dumps(proposal)}}]}

        with self.assertRaisesRegex(RuntimeError, "같은 후보"):
            local.process({"action":"propose", "source": ORIGINAL, "name": "sample.py",
                           "rule": "code.unsafe-deserialization", "model": "sample"}, respond)

    def test_javascript_exports_exclude_comments_and_literals(self):
        source = "export const data = 1;\n/* export const fake = 1; */\n`module.exports = 5`"
        self.assertEqual(local._javascript_api(source), {"esm:data"})

    def test_local_transport_rejects_remote_and_credentials(self):
        for base in ("https://example.com/v1", "http://localhost@bad.test/v1", "http://127.0.0.1:40/path"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                local.local_request(base, "", "models")

    def test_missing_rule_secret_and_device_filename(self):
        for name, source in (("aux.py", ORIGINAL), ("sample.py", "x = 3\n"),
                             ("sample.py", 'github_token = "ghp_' + 'aB18z9XY' * 5 + '"\n' + ORIGINAL)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                local.process({"action": "propose", "source": source, "name": name,
                               "model":"test", "rule":"code.unsafe-deserialization"}, self.fail)

    def test_windows_profiles_and_key_are_separate(self):
        from security_scanner.ai import local_profiles as profiles
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", LOCALAPPDATA=directory):
            store = Path(directory)
            entries = {}

            def vault(action, name, key=""):
                if action == "save":
                    entries[name] = key
                if action == "delete":
                    entries.pop(name)
                return entries.get(name, "")

            with patch.object(profiles, "Path", return_value=store), patch.object(profiles, "_vault", vault), \
                    patch.object(profiles.os, "name", "nt"):
                base = "http://127.0.0.1:1234/v1"
                saved = profiles.with_profile({"action":"save-profile", "base":base, "model":"test", "key":"hidden"})
                self.assertEqual(saved, {"profiles":[{"base":base,"model":"test"}]})
                data = {"action":"models", "base":base, "model":"test"}
                profiles.with_profile(data)
                self.assertEqual(data["key"], "hidden")
                self.assertNotIn(b"hidden", (store / "KODA" / "local-ai.sqlite3").read_bytes())
                self.assertEqual(profiles.with_profile({"action":"delete-profile","base":base,"model":"test"}), {"profiles":[]})
                self.assertFalse(entries)
