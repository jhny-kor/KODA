"""Labeled precision/recall benchmark for Python source-to-sink analysis.

Two corpora: ``python_taint`` (written alongside the AST engine) and
``python_taint_heldout`` (written *after* it, never tuned against — it measures
generalization). Its ``*_LIMIT`` case is a documented ceiling (taint through a
function parameter) and is counted, not hidden. Each fixture declares its
expectation on the first line::

    # koda-bench: expect=vulnerable rule=code.command-injection
    # koda-bench: expect=clean rule=code.command-injection

A fixture is scored only for its declared rule. ``confirmed`` counts findings
that would trip a ``--fail-on`` gate; ``any`` also counts ``needs_review``
candidates. Run this file directly to print the per-class table.
"""

from __future__ import annotations

import re
import sys
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.checks import code_patterns
from security_scanner.models import TargetConfig

FIXTURES_ROOT = ROOT / "tests" / "fixtures"
FIXTURE_DIRS = (FIXTURES_ROOT / "python_taint", FIXTURES_ROOT / "python_taint_heldout")
_HEADER = re.compile(r"#\s*koda-bench:\s*expect=(vulnerable|clean)\s+rule=([\w.-]+)")

# Regression floors for the confirmed (gate) view. Raise these only when the
# analyzer measurably improves; never lower them to make a change pass.
MIN_CONFIRMED_PRECISION = 1.0
MIN_CONFIRMED_RECALL = 0.95


def _cases(dirs=FIXTURE_DIRS) -> list[tuple[Path, bool, str]]:
    cases = []
    for path in sorted(p for d in dirs for p in d.glob("*.py")):
        match = _HEADER.search(path.read_text(encoding="utf-8").splitlines()[0])
        if match:
            cases.append((path, match.group(1) == "vulnerable", match.group(2)))
    return cases


def run_bench(dirs=FIXTURE_DIRS) -> dict[str, object]:
    target = TargetConfig(name="bench", path=FIXTURES_ROOT)
    counts: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: {view: {"tp": 0, "fp": 0, "fn": 0} for view in ("confirmed", "any")}
    )
    outcomes: list[tuple[str, str, str, str]] = []
    for path, positive, rule in _cases(dirs):
        hits = [f for f in code_patterns.check_file(path, target) if f.rule_id == rule]
        flagged = {
            "confirmed": any(f.verification_status == "confirmed" for f in hits),
            "any": bool(hits),
        }
        for view, hit in flagged.items():
            bucket = counts[rule][view]
            if positive:
                bucket["tp" if hit else "fn"] += 1
            elif hit:
                bucket["fp"] += 1
        status = "confirmed" if flagged["confirmed"] else ("candidate" if flagged["any"] else "none")
        outcomes.append((path.stem, rule, "vulnerable" if positive else "clean", status))
    return {"counts": counts, "outcomes": outcomes}


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0


def summarize(counts) -> dict[str, dict[str, float]]:
    totals = {view: {"tp": 0, "fp": 0, "fn": 0} for view in ("confirmed", "any")}
    for per_view in counts.values():
        for view, bucket in per_view.items():
            for key, value in bucket.items():
                totals[view][key] += value
    summary = {}
    for view, bucket in totals.items():
        precision = _ratio(bucket["tp"], bucket["tp"] + bucket["fp"])
        recall = _ratio(bucket["tp"], bucket["tp"] + bucket["fn"])
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        summary[view] = {"precision": precision, "recall": recall, "f1": f1, **bucket}
    return summary


def render_table(result) -> str:
    rows = ["rule                          view       TP FP FN  precision recall"]
    for rule in sorted(result["counts"]):
        for view in ("confirmed", "any"):
            b = result["counts"][rule][view]
            rows.append(
                f"{rule:29} {view:9} {b['tp']:3}{b['fp']:3}{b['fn']:3}  "
                f"{_ratio(b['tp'], b['tp'] + b['fp']):9.2f} {_ratio(b['tp'], b['tp'] + b['fn']):6.2f}"
            )
    for view, s in summarize(result["counts"]).items():
        rows.append(f"{'TOTAL':29} {view:9} {s['tp']:3}{s['fp']:3}{s['fn']:3}  {s['precision']:9.2f} {s['recall']:6.2f}  F1={s['f1']:.2f}")
    return "\n".join(rows)


class PythonTaintBenchmark(unittest.TestCase):
    def test_corpus_is_labeled_and_balanced(self):
        cases = _cases()
        self.assertGreaterEqual(len(cases), 30)
        per_rule = defaultdict(lambda: [0, 0])
        for _path, positive, rule in cases:
            per_rule[rule][0 if positive else 1] += 1
        for rule, (pos, neg) in per_rule.items():
            self.assertGreater(pos, 0, rule)
            self.assertGreater(neg, 0, rule)

    def test_confirmed_view_meets_regression_floor(self):
        result = run_bench()
        summary = summarize(result["counts"])["confirmed"]
        self.assertGreaterEqual(summary["precision"], MIN_CONFIRMED_PRECISION, render_table(result))
        self.assertGreaterEqual(summary["recall"], MIN_CONFIRMED_RECALL, render_table(result))

    def test_known_parameter_flow_limit_still_surfaces_as_candidate(self):
        # The documented ceiling must not silently vanish: the line engine keeps
        # it visible as a needs_review candidate even though AST cannot confirm it.
        outcomes = {name: status for name, _rule, _expect, status in run_bench()["outcomes"]}
        self.assertIn(outcomes["cmd_h_param_flow_LIMIT"], {"candidate", "confirmed"})


if __name__ == "__main__":
    result = run_bench()
    print(render_table(result))
    print()
    for name, rule, expect, status in result["outcomes"]:
        wrong = (expect == "vulnerable" and status != "confirmed") or (expect == "clean" and status == "confirmed")
        print(f"{'MISS' if wrong else 'ok  '} {name:28} expect={expect:10} got={status}")
