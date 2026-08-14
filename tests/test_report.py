"""Slice 4: the report, which is where a careful investigation usually stops
being checkable.

The findings were bound to evidence. The report is prose about them, and by the
time a reader has it the two can only be compared by hand. So these tests are
about the properties that make that comparison unnecessary: the report is
rendered from the ledger, it re-reads rather than quotes, it has no clock in it,
and it refuses to be issued when something it depends on has stopped holding.
"""

import pytest

from witness import report as report_module
from witness.store import Store, sha256_text
from witness.verify import Binding, submit_finding

from conftest import EMBEDDED_C2


def render(store):
    built = report_module.build(store)
    return built, report_module.render_markdown(built)


# ------------------------------------------------------------ what it contains


def test_the_report_carries_the_findings_and_what_would_have_refuted_them(case):
    built, text = render(case)

    assert built.counts["findings"] == 2
    assert EMBEDDED_C2 in text
    assert "domain_appears_in_execution_context" in text
    assert "corroborated" in text
    # The rationale travels with the check, so a reader sees why it was asked.
    assert "every domain in every mail the user ever opened is in there too" in text


def test_the_rejections_are_in_the_body_not_an_appendix(case):
    built, text = render(case)

    assert built.counts["rejections"] == 2
    assert "## Not admitted (2)" in text
    assert "www.venetodns.trade" in text
    assert "Attribute it" in text, "the refusal says what would settle it"

    findings_at = text.index("## Findings")
    rejections_at = text.index("## Not admitted")
    integrity_at = text.index("## Integrity")
    assert findings_at < rejections_at < integrity_at


def test_the_evidence_manifest_names_every_capture_and_its_hash(case):
    built, text = render(case)

    assert built.counts["tool_calls"] == 7
    for item in built.evidence:
        assert item.output_sha256 in text
    derived = [e for e in built.evidence if e.mode == "derived"]
    assert {e.tool for e in derived} == {"decode.unwrap", "indicators.extract"}
    assert any("string_hit record(s)" in source for e in derived for source in e.read_from)


def test_provenance_follows_the_record_not_the_whole_tool_call(case):
    """The extractor swept four record kinds. This domain came from one of them."""
    built, _ = render(case)
    domain = next(f for f in built.findings if f.finding_type == "malicious_domain")

    assert domain.provenance == [
        "indicators.extract <- decode.unwrap <- strings <- base-wkstn-05-memory.img"
    ]
    assert "netscan" not in domain.provenance[0], "netscan is not on this domain's path"


def test_a_report_may_be_scoped_to_one_host(case):
    built = report_module.build(case, host="base-wkstn-01")
    assert built.hosts == ["base-wkstn-01"]
    assert built.findings == []
    assert all(e.host == "base-wkstn-01" for e in built.evidence)


def test_the_json_rendering_carries_the_same_verdicts(case):
    import json

    built, _ = render(case)
    payload = json.loads(report_module.render_json(built))
    assert payload["counts"] == built.counts
    assert payload["issuable"] is True
    outcomes = {c["outcome"] for f in payload["findings"] for c in f["checks"]}
    assert outcomes == {"corroborated"}


# --------------------------------------------------------------- reproducible


def test_the_same_case_renders_the_same_bytes(case):
    """No clock in the output, so the hash of a report is a fact about the case."""
    first = report_module.render_markdown(report_module.build(case))
    second = report_module.render_markdown(report_module.build(case))
    assert first == second


def test_issuing_a_report_does_not_change_what_it_says(case):
    """Issuing appends an entry. If that moved the quoted head, no report could
    ever be re-rendered - so a report commits to the case, not to the chain."""
    built, text = render(case)
    entry = report_module.issue(case, built, text)

    assert entry["report_sha256"] == sha256_text(text)
    assert entry["chain_head"] == built.chain_head
    assert case.head() != case.case_head(), "the report entry is in the chain"

    _, again = render(case)
    assert again == text


# ------------------------------------------------------------ what it refuses


def test_a_report_re_reads_every_value_rather_than_quoting_the_finding(case, tmp_path):
    record = case.query_records(kind="process", where={"pid": 3720})[0]
    case.db.execute(
        "UPDATE records SET fields = ? WHERE record_id = ?",
        ('{"pid": 3720, "ppid": 9999, "image_file_name": "rundll32.exe"}', record["record_id"]),
    )
    case.db.commit()

    built, text = render(case)
    assert not built.issuable
    assert "**This report is not issuable.**" in text
    assert any("no longer matches the chain entry" in p for p in built.problems)
    assert any(
        b.problem and "the finding claims" in b.problem
        for f in built.findings
        for b in f.bindings
    ), "the mismatch is shown on the line where the value would have gone"


def test_an_unissuable_report_cannot_be_issued(case):
    case.db.execute("DELETE FROM records WHERE kind = 'indicator'")
    case.db.commit()

    built, text = render(case)
    with pytest.raises(ValueError, match="refusing to issue"):
        report_module.issue(case, built, text)
    assert case.list_reports() == []


def test_an_edited_report_is_not_recognised(case):
    built, text = render(case)
    report_module.issue(case, built, text)

    tampered = text.replace("www.venetodns.trade", "www.venetodns.trad3")
    result = report_module.check_issued(case, tampered)
    assert result["issued"] is False

    assert report_module.check_issued(case, text)["issued"] is True


def test_a_report_can_be_authentic_and_stale(case):
    """Two different questions: was this issued from here, and is it still true."""
    built, text = render(case)
    report_module.issue(case, built, text)
    assert report_module.check_issued(case, text)["still_current"] is True

    process = case.query_records(kind="process", host="base-wkstn-05", where={"pid": 2676})[0]
    submit_finding(
        case,
        finding_type="process_present",
        claim="WmiPrvSE.exe was running as PID 2676.",
        bindings=[Binding(process["record_id"], "image_file_name", "WmiPrvSE.exe")],
        subject={"pid": 2676},
    )

    result = report_module.check_issued(case, text)
    assert result["issued"] is True, "the bytes were genuinely issued from this store"
    assert result["still_current"] is False, "the case has moved on since"
    assert result["still_holds"] is True, "nothing in it has stopped being true"


def test_an_empty_case_reports_that_nothing_survived(tmp_path):
    store = Store(tmp_path / "empty.db")
    built, text = render(store)
    assert built.counts["findings"] == 0
    assert "No finding survived both gates." in text
    assert built.issuable
