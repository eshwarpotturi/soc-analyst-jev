import json
from pathlib import Path

import pytest

import jev_client

CORPUS = Path(__file__).resolve().parent.parent / "fixtures" / "corpus.jsonl"
FIELDS = {"method", "path", "query", "headers", "body", "true_label", "true_category"}
CATEGORIES = set(jev_client.CATEGORIES)
# The classic corpus covers the signature-based attack classes; semantic classes
# (prompt_injection, data_exfiltration, abuse) live in the separate semantic corpus.
ATTACKS = {"sql_injection", "xss", "path_traversal", "command_injection",
           "ssrf", "auth_bruteforce", "scanner_probe", "other_exploit"}
assert ATTACKS <= CATEGORIES  # stays in sync with the canonical set


@pytest.fixture(scope="module")
def rows():
    with CORPUS.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def test_every_line_has_all_fields(rows):
    for r in rows:
        assert set(r) == FIELDS
        assert isinstance(r["headers"], dict)
        assert isinstance(r["query"], str) and isinstance(r["body"], str)


def test_size_in_range(rows):
    assert 500 <= len(rows) <= 700


def test_label_distribution(rows):
    frac = sum(r["true_label"] == "malicious" for r in rows) / len(rows)
    assert 0.12 <= frac <= 0.18


def test_categories_canonical(rows):
    used = {r["true_category"] for r in rows}
    assert used <= CATEGORIES
    assert set(jev_client.CATEGORIES) >= used
    assert (used - {"none"}) <= set(jev_client.CATEGORIES) - {"none"}


def test_label_category_consistency(rows):
    for r in rows:
        assert r["true_label"] in ("benign", "malicious")
        if r["true_label"] == "benign":
            assert r["true_category"] == "none"
        else:
            assert r["true_category"] != "none"


def test_all_attack_categories_present(rows):
    assert ATTACKS <= {r["true_category"] for r in rows}
