"""Slice 4: re-derive the case and see whether you get the same one back.

Nothing in the store is numbered from a clock or a counter - every id comes from
content - so the chain head is a fingerprint of the case rather than of the
session that produced it. That is only worth asserting if it is checked, and
checking it is what `replay` does: rebuild the whole case into an empty store
from the captures alone, and compare.
"""

import shutil

from conftest import EMBEDDED_C2, build_case

from witness import report as report_module
from witness.replay import index_captures, replay
from witness.store import Store

FIXTURES_ARG = ["fixtures"]


def replayed(case, tmp_path, inputs=FIXTURES_ARG, name="replayed.db"):
    return replay(case, inputs, Store(tmp_path / name))


# ------------------------------------------------------------------- it round-trips


def test_a_case_replays_to_the_same_chain_head(case, tmp_path):
    result = replayed(case, tmp_path)
    assert result.ok, result.report()
    assert result.head_matches
    assert result.replayed_head == case.head()


def test_replay_reproduces_the_findings_with_identical_ids(case, tmp_path):
    result = replayed(case, tmp_path)
    assert result.source_findings == result.replayed_findings
    assert len(result.source_findings) == 2


def test_replay_reproduces_the_rejections_too(case, tmp_path):
    """A case that can only replay what it accepted leaves its refusals as assertions."""
    result = replayed(case, tmp_path)
    assert result.source_rejections == result.replayed_rejections
    assert len(result.source_rejections) == 2

    rebuilt = Store(tmp_path / "again.db")
    replay(case, FIXTURES_ARG, rebuilt)
    reasons = {r["reason"] for r in rebuilt.list_rejections()}
    assert any("Attribute it" in reason for reason in reasons)


def test_the_rebuilt_store_holds_the_same_evidence(case, tmp_path):
    rebuilt = Store(tmp_path / "rebuilt.db")
    replay(case, FIXTURES_ARG, rebuilt)

    for kind in ("process", "network_endpoint", "string_hit", "decoded_payload", "indicator"):
        assert [r["record_id"] for r in rebuilt.query_records(kind=kind)] == [
            r["record_id"] for r in case.query_records(kind=kind)
        ], kind
    assert rebuilt.query_records(kind="indicator", where={"value": EMBEDDED_C2})


def test_a_replayed_case_verifies_on_its_own(case, tmp_path):
    rebuilt = Store(tmp_path / "standalone.db")
    replay(case, FIXTURES_ARG, rebuilt)
    ok, problems = rebuilt.verify_chain()
    assert ok, problems


# --------------------------------------------------------- captures are matched by hash


def test_a_renamed_capture_still_replays(case, tmp_path):
    """Which directory a capture sits in, and what it is called, are not evidence."""
    moved = tmp_path / "some-other-name"
    shutil.copytree("fixtures", moved)
    for index, path in enumerate(sorted(moved.rglob("*.txt"))):
        path.rename(path.with_name(f"capture-{index}.dat"))

    result = replayed(case, tmp_path, inputs=[moved])
    assert result.ok, result.report()


def test_an_edited_capture_does_not_replay_as_itself(case, tmp_path):
    """One character. The point of matching on hash rather than on filename."""
    edited = tmp_path / "edited"
    shutil.copytree("fixtures", edited)
    target = edited / "wkstn05" / "psscan.txt"
    target.write_text(target.read_text().replace("rundll32.exe", "rundll64.exe"), encoding="utf-8")

    result = replayed(case, tmp_path, inputs=[edited])
    assert not result.ok
    assert any("windows.psscan" in item for item in result.missing)
    assert any("no capture matching sha256" in item for item in result.missing)


def test_a_capture_that_was_never_supplied_is_named(case, tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    result = replayed(case, tmp_path, inputs=[empty])
    assert not result.ok
    assert len(result.missing) == 5, "every replay-mode capture is reported, not just the first"


def test_the_capture_index_is_keyed_by_content(tmp_path):
    index = index_captures(["fixtures"])
    assert len(index) == 6, "every capture under fixtures/, including the unused one"
    assert all(len(digest) == 64 for digest in index)
    assert {path.name for path in index.values()} == {
        "psscan.txt",
        "netscan.txt",
        "malfind.txt",
        "strings.txt",
        "malfind_hits.txt",
    }, "two hosts' netscan captures differ, so they are two entries under one name"


# --------------------------------------------------------------- the report replays too


def test_replay_reproduces_an_issued_report_byte_for_byte(case, tmp_path):
    built = report_module.build(case)
    text = report_module.render_markdown(built)
    report_module.issue(case, built, text)

    rebuilt = Store(tmp_path / "with-report.db")
    result = replay(case, FIXTURES_ARG, rebuilt)
    assert result.ok, result.report()

    issued = rebuilt.list_reports()
    assert len(issued) == 1
    assert issued[0]["report_sha256"] == case.list_reports()[0]["report_sha256"]
    assert report_module.render_markdown(report_module.build(rebuilt)) == text


# --------------------------------------------------------------- two runs, one case


def test_two_independent_runs_agree_on_the_head(tmp_path):
    """The property replay depends on, asserted directly."""
    first = build_case(tmp_path / "first.db")
    second = build_case(tmp_path / "second.db")
    assert first.head() == second.head()
    assert first.case_head() == second.case_head()
