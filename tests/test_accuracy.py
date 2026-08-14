"""The accuracy corpus, run as a test.

`scripts/accuracy.py` prints the argument. This asserts it, so a change that
quietly costs recall - or quietly starts admitting something it should refuse -
fails the build rather than showing up as a slightly different number in a
report nobody re-reads.

The whole corpus is scored once for the module. It is the slowest thing in the
suite by some distance, and it is a thousand claims against a real case, so that
seems a fair trade.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import corpus
from witness import casefile, report
from witness.store import Store

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


@pytest.fixture(scope="module")
def scored(tmp_path_factory):
    store = Store(tmp_path_factory.mktemp("accuracy") / "case.db")
    casefile.load(store, FIXTURES)
    built = corpus.build(store, FIXTURES)
    outcomes = [corpus.judge(store, case) for case in built.cases]
    return store, built, outcomes


# ------------------------------------------------------------- the corpus itself


def test_the_corpus_builds_with_no_gaps(scored):
    _, built, _ = scored
    assert built.problems == [], "a corpus that shrinks quietly reports breakage as a clean sweep"


def test_the_corpus_is_the_size_it_claims_to_be(scored):
    _, built, _ = scored
    assert len(built.cases) >= 1000
    assert len(corpus.CLASSES) >= 29
    names = [case.name for case in built.cases]
    assert len(names) == len(set(names)), "two cases under one name means one of them is unmeasured"


def test_every_class_is_exercised(scored):
    _, built, _ = scored
    empty = [c.name for c in corpus.CLASSES if not built.by_class(c.name)]
    assert not empty, f"classes that produced no cases: {empty}"


def test_both_halves_are_populated(scored):
    """A tool that refuses everything scores perfectly on precision alone."""
    _, built, _ = scored
    sound = [c for c in built.cases if c.truth == corpus.SOUND]
    mistaken = [c for c in built.cases if c.truth == corpus.MISTAKEN]
    assert len(sound) >= 400
    assert len(mistaken) >= 400


def test_the_census_covers_every_row_of_every_capture(scored):
    """The census is only a census if nothing was left out of it."""
    store, built, _ = scored
    census = built.by_class("field_census_captured") + built.by_class("field_census_strings")
    parsed = [
        record
        for record in store.query_records()
        if record["kind"] in ("process", "network_endpoint", "host_fact", "string_hit")
    ]
    assert len(census) == len(parsed)


# ----------------------------------------------------------------- the results


def test_no_false_claim_was_admitted(scored):
    _, _, outcomes = scored
    admitted = [o for o in outcomes if o.admitted and o.case.truth == corpus.MISTAKEN]
    assert not admitted, [(o.case.error_class, o.case.name) for o in admitted]


def test_no_true_claim_was_refused(scored):
    _, _, outcomes = scored
    refused = [o for o in outcomes if not o.admitted and o.case.truth == corpus.SOUND]
    assert not refused, [(o.case.error_class, o.case.name, o.reason) for o in refused]


def test_every_refusal_named_the_actual_defect(scored):
    """Stopping the right claim for the wrong reason is luck, not accuracy."""
    _, _, outcomes = scored
    misnamed = [o for o in outcomes if o.right_reason is False]
    assert not misnamed, [(o.case.name, o.case.marker, o.reason) for o in misnamed]


@pytest.mark.parametrize("error_class", corpus.CLASSES, ids=lambda c: c.name)
def test_class_scores_perfectly(scored, error_class):
    _, _, outcomes = scored
    got = [o for o in outcomes if o.case.error_class == error_class.name]
    assert got, f"{error_class.name} produced no cases"
    wrong = [o for o in got if not o.correct]
    assert not wrong, [(o.case.name, o.reason) for o in wrong]


def test_the_ledger_survives_the_whole_run(scored):
    store, _, outcomes = scored
    ok, problems = store.verify_chain()
    assert ok, problems[:3]
    admitted = sum(1 for o in outcomes if o.admitted)
    assert len(store.list_findings()) == admitted
    for host in casefile.HOSTS:
        assert report.build(store, host=host).issuable


# --------------------------------------------- the harness has to be able to fail


def test_a_dropped_row_breaks_the_census_rather_than_shrinking_it(tmp_path):
    """If the parser lost a row, the corpus must say so, not quietly measure less.

    This is the property that makes the numbers above worth anything. The census
    lines the capture's rows up with the store's records by position, so a row
    that never became a record puts every later pair out of step - and the run
    has to notice that rather than generate one case fewer and still report a
    clean sweep.
    """
    store = Store(tmp_path / "case.db")
    casefile.load(store, FIXTURES)
    victim = store.query_records(kind="process", host=corpus.WKSTN05)[10]
    store.db.execute("DELETE FROM records WHERE record_id = ?", (victim["record_id"],))
    store.db.commit()

    built = corpus.build(store, FIXTURES)
    assert any("cannot be lined up" in problem for problem in built.problems)
    assert not built.by_class("field_census_captured") or all(
        case.name.split(":")[1] != "windows.psscan"
        for case in built.by_class("field_census_captured")
    )
