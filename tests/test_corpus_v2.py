import make_corpus
from jev_client import CATEGORIES


def test_default_build_matches_committed_shape():
    rows = make_corpus.build(make_corpus.SEED, make_corpus.N_BENIGN)
    assert len(rows) == make_corpus.N_BENIGN + len(make_corpus.malicious(__import__("random").Random(0)))
    assert all(r["true_category"] in set(CATEGORIES) for r in rows)


def test_augmented_build_counts_and_labels():
    rows = make_corpus.build(seed=2026, n_benign=680, n_attacks=120)
    assert len(rows) == 800
    mal = [r for r in rows if r["true_label"] == "malicious"]
    ben = [r for r in rows if r["true_label"] == "benign"]
    assert len(mal) == 120 and len(ben) == 680
    assert all(r["true_category"] != "none" for r in mal)
    assert all(r["true_category"] in set(CATEGORIES) for r in rows)
    # every attack category from the base pool still appears
    assert len({r["true_category"] for r in mal}) >= 6


def test_augmentation_is_seed_deterministic():
    a = make_corpus.build(seed=2026, n_benign=50, n_attacks=30)
    b = make_corpus.build(seed=2026, n_benign=50, n_attacks=30)
    assert a == b


def test_default_build_is_unchanged_vs_committed():
    committed = [__import__("json").loads(l) for l in
                 (__import__("pathlib").Path("fixtures/corpus.jsonl")).read_text().splitlines() if l.strip()]
    assert make_corpus.build(make_corpus.SEED, make_corpus.N_BENIGN) == committed
