"""Regression checks for the active YARA rules and synthetic corpus."""

import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RULES_PATH = ROOT / "data" / "rules" / "everbloom_core.yar"
MANIFEST_PATH = ROOT / "tests" / "corpus" / "manifest.json"


def test_active_yara_rules_compile_and_match_regression_corpus() -> None:
    yara = pytest.importorskip("yara")
    rules = yara.compile(filepath=str(RULES_PATH))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    false_positives = []
    false_negatives = []
    for sample in manifest["samples"]:
        path = ROOT / "tests" / "corpus" / sample["path"]
        matches = {match.rule for match in rules.match(str(path))}
        expected = set(sample.get("expected_rules", []))
        if sample["label"] == 0 and matches:
            false_positives.append((sample["path"], sorted(matches)))
        if sample["label"] == 1 and not expected.issubset(matches):
            false_negatives.append((sample["path"], sorted(expected - matches)))

    assert not false_positives, f"YARA false positives: {false_positives}"
    assert not false_negatives, f"YARA false negatives: {false_negatives}"
