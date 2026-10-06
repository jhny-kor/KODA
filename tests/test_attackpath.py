from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner import attackpath
from security_scanner.models import Finding


def _f(rule_id: str, target: str = "http://h/", severity: str = "high") -> Finding:
    return Finding(rule_id=rule_id, category="web", severity=severity, title=rule_id,
                   path=Path(target), target=target, evidence="e")


class CorrelateTests(unittest.TestCase):
    def test_metadata_ssrf_becomes_credential_theft_path(self):
        paths = attackpath.correlate([_f("web.ssrf-cloud-metadata", severity="critical")])
        self.assertIn("attack-path.metadata-credential-theft", {p.rule_id for p in paths})

    def test_docker_unauth_becomes_host_takeover_path(self):
        paths = attackpath.correlate([_f("net.docker-unauth")])
        ids = {p.rule_id for p in paths}
        self.assertIn("attack-path.docker-host-takeover", ids)

    def test_unrelated_findings_produce_no_paths(self):
        self.assertEqual(attackpath.correlate([_f("web.reflected-xss-verified", severity="medium")]), [])

    def test_paths_are_per_target(self):
        findings = [_f("web.ssrf-cloud-metadata", target="http://a/"), _f("net.docker-unauth", target="http://b/")]
        paths = attackpath.correlate(findings)
        targets = {p.target for p in paths}
        self.assertEqual(targets, {"http://a/", "http://b/"})


class NarrateTests(unittest.TestCase):
    def test_narrative_appended_to_high_impact_finding(self):
        from security_scanner.ai import narrate, provider

        path = attackpath.correlate([_f("net.docker-unauth")])[0]

        def fake_complete(prompt, *, system, json_mode, model, timeout_seconds):
            return provider.LLMResult(text="An attacker launches a privileged container.", backend="test", sent_externally=False)

        out, warnings = narrate.explain_findings([path], complete=fake_complete)
        self.assertIn("AI: An attacker launches a privileged container.", out[0].description)
        self.assertEqual(warnings, [])

    def test_low_impact_finding_is_left_alone(self):
        from security_scanner.ai import narrate, provider

        finding = _f("web.reflected-xss-verified", severity="medium")

        def fake_complete(*a, **k):  # must not be called
            raise AssertionError("should not narrate a low-impact finding")

        out, _ = narrate.explain_findings([finding], complete=fake_complete)
        self.assertEqual(out[0].description, finding.description)


class RemediateTests(unittest.TestCase):
    def test_fix_suggestion_appended_to_recommendation(self):
        from security_scanner.ai import provider, remediate

        finding = Finding(rule_id="web.reflected-xss-verified", category="web", severity="medium",
                          title="Reflected XSS", path=Path("http://h/"), target="http://h/",
                          evidence="marker reflected", recommendation="Encode output.")

        def fake_complete(prompt, *, system, json_mode, model, timeout_seconds):
            return provider.LLMResult(text="HTML-encode the value before echoing it.", backend="test", sent_externally=False)

        out, warnings = remediate.remediate_findings([finding], complete=fake_complete)
        self.assertIn("Suggested fix: HTML-encode the value", out[0].recommendation)
        self.assertIn("Encode output.", out[0].recommendation)
        self.assertEqual(warnings, [])

    def test_triage_false_positive_is_not_remediated(self):
        from dataclasses import replace

        from security_scanner.ai import remediate

        finding = replace(
            Finding(rule_id="web.reflected-xss-verified", category="web", severity="medium",
                    title="x", path=Path("http://h/"), target="http://h/", evidence="e"),
            triage_verdict="likely_false",
        )

        def fake_complete(*a, **k):
            raise AssertionError("should not remediate a likely-false-positive finding")

        out, _ = remediate.remediate_findings([finding], complete=fake_complete)
        self.assertEqual(out[0].recommendation, finding.recommendation)


if __name__ == "__main__":
    unittest.main()
