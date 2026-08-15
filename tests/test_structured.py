"""The structured-response collector: the gate applied to something that is not a dump.

The point of these tests is not that JSON parses. It is that a response from a
service arrives in the store on exactly the terms a Volatility table does - one
addressable record per thing, every value re-readable, nothing shortened, nothing
judged - so a claim about what a service said is refused on the same grounds as a
claim about what a process table said.

The fixture is synthetic and says so: `example-c2.invalid` is reserved by RFC 2606
and cannot be anyone's real infrastructure. It corroborates nothing in the case.
"""

import json
from pathlib import Path

import pytest

from witness.collectors import structured
from witness.replay import replay
from witness.store import Store
from witness.verify import Binding, submit_finding, verify

SYNTHETIC = Path(__file__).resolve().parent.parent / "fixtures" / "synthetic"
FIXTURE = SYNTHETIC / "reputation_lookup.json"
CSV_FIXTURE = SYNTHETIC / "detections.csv"
JSONL_FIXTURE = SYNTHETIC / "detections.jsonl"


def read() -> str:
    return FIXTURE.read_text()


def write(tmp_path, document, name="response.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document))
    return path


def ingest(store, path, **kwargs):
    kwargs.setdefault("tool", "reputation_lookup")
    return structured.ingest_capture(store, output_path=path, **kwargs)


# ------------------------------------------------------------------ flattening


def test_a_nested_value_gets_a_name_a_binding_can_use():
    fields = structured.parse(read()).rows[0]
    assert fields["data.attributes.last_analysis_stats.malicious"] == 12
    assert fields["query.indicator"] == "example-c2.invalid"


def test_types_survive_the_flattening():
    """JSON already has real types. Losing them would make every claim a string."""
    fields = structured.parse(read()).rows[0]
    assert fields["data.attributes.reputation"] == -37
    assert isinstance(fields["data.attributes.reputation"], int)
    assert fields["data.attributes.confidence"] == 0.87
    assert fields["data.attributes.harmless"] is False


def test_list_elements_are_addressed_by_index():
    fields = structured.parse(read()).rows[0]
    assert fields["data.attributes.tags.0"] == "parked"
    assert fields["data.attributes.tags.1"] == "newly-registered"
    assert fields["engines.2.verdict"] == "malicious"


def test_null_is_kept_as_null():
    fields = structured.parse(read()).rows[0]
    assert fields["data.attributes.registrar"] is None
    assert "data.attributes.registrar" in fields


def test_an_empty_container_is_recorded_rather_than_dropped():
    """"reported no categories" and "was never asked" are different refusals."""
    fields = structured.parse(read()).rows[0]
    assert fields["data.attributes.categories"] == "[]"
    assert fields["data.relationships"] == "{}"


def test_nothing_is_truncated():
    """These records are the store's only copy of what the response said."""
    whois = structured.parse(read()).rows[0]["data.attributes.whois"]
    assert whois == json.loads(read())["data"]["attributes"]["whois"]
    assert "\n" in whois


def test_two_values_that_flatten_to_one_path_are_refused_not_guessed():
    fields, problems = structured.flatten({"a": {"b": 1}, "a.b": 2})
    assert problems
    assert "'a.b'" in problems[0]
    assert fields["a.b"] == 1  # the caller drops the record; it never reaches the store


def test_an_ambiguous_record_is_skipped_with_a_reason(tmp_path):
    result = structured.parse(json.dumps({"a": {"b": 1}, "a.b": 2}))
    assert result.rows == []
    assert len(result.skipped) == 1
    assert "a.b" in result.skipped[0]


# ------------------------------------------------------------- record selection


def test_a_path_selects_the_record_set():
    result = structured.parse(read(), "engines")
    assert len(result.rows) == 3
    assert [row["engine"] for row in result.rows] == ["alpha", "bravo", "charlie"]


def test_a_path_can_walk_into_a_list():
    fields = structured.parse(read(), "engines.1").rows[0]
    assert fields["engine"] == "bravo"


def test_a_missing_path_says_what_is_there_instead():
    with pytest.raises(structured.ParseError) as exc:
        structured.parse(read(), "detections")
    assert "no key 'detections'" in str(exc.value)
    assert "engines" in str(exc.value)


def test_a_scalar_cannot_be_a_record_set():
    with pytest.raises(structured.ParseError) as exc:
        structured.parse(read(), "query.type")
    assert "not an object or a list of objects" in str(exc.value)


def test_a_list_of_scalars_is_reported_not_synthesised(tmp_path):
    """Inventing a field name for a bare string would be the collector judging."""
    result = structured.parse(json.dumps({"tags": ["a", "b"]}), "tags")
    assert result.rows == []
    assert len(result.skipped) == 2
    assert "not an object" in result.skipped[0]


def test_not_json_at_all_is_a_parse_error():
    with pytest.raises(structured.ParseError) as exc:
        structured.parse("Volatility 3 Framework 2.27.0\nPID\tPPID\n")
    assert "not readable json" in str(exc.value)


# -------------------------------------------------------------------- ingestion


def test_ingest_records_the_service_as_the_tool(tmp_path):
    store = Store(tmp_path / "case.db")
    result = ingest(store, FIXTURE, records_at="engines", host="soc")
    call = store.get_tool_call(result["tool_call_id"])
    assert call["tool"] == "response.reputation_lookup"
    assert call["mode"] == "replay"
    assert result["records"] == 3
    assert store.query_records(kind="reputation_lookup", host="soc")


def test_the_kind_defaults_to_the_source_and_can_be_overridden(tmp_path):
    store = Store(tmp_path / "case.db")
    ingest(store, FIXTURE, records_at="engines", kind="engine_verdict")
    assert len(store.query_records(kind="engine_verdict")) == 3
    assert store.query_records(kind="reputation_lookup") == []


def test_the_request_is_kept_alongside_the_response(tmp_path):
    """A response with no record of its question cannot be re-asked."""
    store = Store(tmp_path / "case.db")
    result = ingest(store, FIXTURE, evidence_path="GET /domains/example-c2.invalid")
    assert store.get_tool_call(result["tool_call_id"])["evidence_path"] == (
        "GET /domains/example-c2.invalid"
    )


def test_re_ingesting_the_same_response_is_a_no_op(tmp_path):
    store = Store(tmp_path / "case.db")
    first = ingest(store, FIXTURE, records_at="engines")
    second = ingest(store, FIXTURE, records_at="engines")
    assert first["tool_call_id"] == second["tool_call_id"]
    assert first["record_ids"] == second["record_ids"]
    assert len(store.query_records(kind="reputation_lookup")) == 3


def test_the_same_response_read_at_two_paths_is_two_tool_calls(tmp_path):
    """Different records out means a different call, even from identical bytes."""
    store = Store(tmp_path / "case.db")
    whole = ingest(store, FIXTURE)
    engines = ingest(store, FIXTURE, records_at="engines")
    assert whole["tool_call_id"] != engines["tool_call_id"]
    assert store.get_tool_call(whole["tool_call_id"])["output_sha256"] == (
        store.get_tool_call(engines["tool_call_id"])["output_sha256"]
    )


def test_a_response_with_no_source_named_is_refused(tmp_path):
    store = Store(tmp_path / "case.db")
    with pytest.raises(ValueError):
        structured.ingest_capture(store, tool="  ", output_path=FIXTURE)


def test_the_chain_holds_after_ingesting_a_response(tmp_path):
    store = Store(tmp_path / "case.db")
    ingest(store, FIXTURE, records_at="engines")
    ok, problems = store.verify_chain()
    assert ok, problems


# ------------------------------------------------------------------------- gate


def bound(tmp_path, **kwargs):
    store = Store(tmp_path / "case.db")
    ingest(store, FIXTURE, **kwargs)
    return store


def test_the_gate_admits_a_claim_that_quotes_the_response(tmp_path):
    store = bound(tmp_path)
    record = store.query_records(kind="reputation_lookup")[0]["record_id"]
    verdict = verify(
        store,
        "The service reported 12 malicious engine detections.",
        [Binding(record, "data.attributes.last_analysis_stats.malicious", 12)],
    )
    assert verdict.accepted, verdict.report()


def test_the_gate_refuses_a_claim_that_misquotes_the_response(tmp_path):
    """The failure mode this exists for: the tool ran, and the number is wrong."""
    store = bound(tmp_path)
    record = store.query_records(kind="reputation_lookup")[0]["record_id"]
    verdict = verify(
        store,
        "The service reported 47 malicious engine detections.",
        [Binding(record, "data.attributes.last_analysis_stats.malicious", 47)],
    )
    assert not verdict.accepted
    assert "record says 12" in verdict.refutation


def test_the_gate_refuses_a_field_the_response_never_carried(tmp_path):
    store = bound(tmp_path)
    record = store.query_records(kind="reputation_lookup")[0]["record_id"]
    verdict = verify(
        store,
        "The service classified the domain as ransomware infrastructure.",
        [Binding(record, "data.attributes.threat_family", "ransomware")],
    )
    assert not verdict.accepted
    assert "no field" in verdict.refutation


def test_a_boolean_field_does_not_answer_a_numeric_claim(tmp_path):
    store = bound(tmp_path)
    record = store.query_records(kind="reputation_lookup")[0]["record_id"]
    verdict = verify(store, "harmless was 0.", [Binding(record, "data.attributes.harmless", 0)])
    assert not verdict.accepted
    assert "boolean" in verdict.refutation


def test_a_response_backed_finding_reaches_the_ledger(tmp_path):
    store = bound(tmp_path, records_at="engines", kind="engine_verdict")
    record = store.query_records(kind="engine_verdict", where={"engine": "charlie"})[0]["record_id"]
    verdict, finding_id = submit_finding(
        store,
        finding_type="observation",
        claim="One engine categorised example-c2.invalid as phishing.",
        bindings=[
            Binding(record, "engine", "charlie"),
            Binding(record, "category", "phishing"),
        ],
    )
    assert verdict.accepted, verdict.report()
    assert finding_id
    assert store.list_findings()[0]["finding_id"] == finding_id


def test_provenance_walks_a_response_record_back_to_its_call(tmp_path):
    store = bound(tmp_path, records_at="engines", evidence_path="GET /domains/example-c2.invalid")
    record = store.query_records(kind="reputation_lookup")[0]["record_id"]
    trail = store.provenance(record)
    assert [call["tool"] for call in trail] == ["response.reputation_lookup"]
    assert trail[0]["evidence_path"] == "GET /domains/example-c2.invalid"


# ----------------------------------------------------------------------- replay


def test_a_response_backed_case_replays_to_the_same_head(tmp_path):
    """Replay rebuilds from the chain alone, so the read path has to survive it."""
    store = Store(tmp_path / "case.db")
    ingest(store, FIXTURE, records_at="engines", kind="engine_verdict", host="soc")
    record = store.query_records(kind="engine_verdict", where={"engine": "alpha"})[0]["record_id"]
    submit_finding(
        store,
        finding_type="observation",
        claim="Engine alpha returned a malicious verdict.",
        bindings=[Binding(record, "verdict", "malicious")],
    )
    submit_finding(
        store,
        finding_type="observation",
        claim="Engine alpha returned a benign verdict.",
        bindings=[Binding(record, "verdict", "benign")],
    )

    result = replay(store, ["fixtures"], Store(tmp_path / "replayed.db"))
    assert result.ok, result.report()
    assert result.replayed_head == store.head()
    assert len(result.replayed_rejections) == 1


def test_replay_recovers_the_read_options_from_the_recorded_argv():
    argv = structured.argv_for("reputation_lookup", "engine_verdict", "engines", "json")
    assert structured.from_argv(argv) == {
        "tool": "reputation_lookup",
        "kind": "engine_verdict",
        "records_at": "engines",
        "fmt": "json",
    }


def test_an_argv_written_before_formats_existed_still_means_json():
    """Additive, like the store's own migrations: an older store still replays."""
    argv = ["witness", "ingest", "--tool", "response", "--source", "x",
            "--kind", "x", "--records-at", "."]
    assert structured.from_argv(argv)["fmt"] == "json"


def test_replay_reports_an_argv_it_cannot_read():
    with pytest.raises(structured.ParseError):
        structured.from_argv(["witness", "ingest", "--tool", "response"])


# -------------------------------------------------------------------------- cli


def test_cli_ingests_a_response(tmp_path, capsys):
    from witness.cli import main

    code = main([
        "--store", str(tmp_path / "case.db"),
        "ingest", "--tool", "response", "--source", "reputation_lookup",
        "--records-at", "engines", "--kind", "engine_verdict",
        "--input", str(FIXTURE),
    ])
    out = capsys.readouterr().out
    assert code == 0
    assert "response.reputation_lookup" in out
    assert "records     3 of kind engine_verdict" in out


def test_cli_refuses_a_response_with_no_source(tmp_path, capsys):
    from witness.cli import main

    code = main([
        "--store", str(tmp_path / "case.db"),
        "ingest", "--tool", "response", "--input", str(FIXTURE),
    ])
    assert code == 1
    assert "--source" in capsys.readouterr().out


def test_cli_reports_an_unreadable_response(tmp_path, capsys):
    from witness.cli import main

    bad = tmp_path / "not.json"
    bad.write_text("PID\tPPID\n3720\t1332\n")
    code = main([
        "--store", str(tmp_path / "case.db"),
        "ingest", "--tool", "response", "--source", "whatever", "--input", str(bad),
    ])
    assert code == 1
    assert "not readable json" in capsys.readouterr().out


# ------------------------------------------------------------ delimited and jsonl
#
# Most of what a SOC gets back is not a JSON document - it is a header row and
# some lines. The gate should not care, and these say so.


def csv_rows(text=None):
    return structured.parse(text if text is not None else CSV_FIXTURE.read_text(), fmt="csv").rows


def test_the_header_row_names_the_fields():
    rows = csv_rows()
    assert len(rows) == 3
    assert rows[0]["detection_id"] == "D-1001"
    assert rows[0]["technique"] == "T1059.001"
    assert set(rows[0]) == {
        "detection_id", "device", "severity", "account_id",
        "technique", "first_seen", "description",
    }


def test_a_quoted_cell_keeps_its_delimiter():
    """Splitting on commas by hand would make this row two fields short."""
    assert csv_rows()[0]["description"] == (
        "PowerShell spawned by wmiprvse.exe, encoded command"
    )


def test_an_empty_cell_is_an_empty_cell_not_a_missing_field():
    row = csv_rows()[2]
    assert row["severity"] == ""
    assert "severity" in row


def test_cells_are_stored_as_text_and_not_typed_at_ingest():
    """A delimited file carries no types. Inventing them would lose a leading zero."""
    row = csv_rows()[0]
    assert row["severity"] == "70"
    assert row["account_id"] == "00417"


def test_a_numeric_claim_still_binds_to_a_text_cell(tmp_path):
    store = Store(tmp_path / "case.db")
    ingest(store, CSV_FIXTURE, tool="edr_export", fmt="csv")
    record = store.query_records(kind="edr_export", where={"detection_id": "D-1001"})[0]
    verdict = verify(store, "Severity was 70.", [Binding(record["record_id"], "severity", 70)])
    assert verdict.accepted, verdict.report()


def test_a_padded_identifier_does_not_answer_to_its_unpadded_number(tmp_path):
    """00417 is an account, not the number 417. The gate has to keep them apart."""
    store = Store(tmp_path / "case.db")
    ingest(store, CSV_FIXTURE, tool="edr_export", fmt="csv")
    record = store.query_records(kind="edr_export", where={"detection_id": "D-1001"})[0]
    wrong = verify(store, "Account 417 was involved.",
                   [Binding(record["record_id"], "account_id", 417)])
    assert not wrong.accepted
    assert "record says '00417'" in wrong.refutation

    right = verify(store, "Account 00417 was involved.",
                   [Binding(record["record_id"], "account_id", "00417")])
    assert right.accepted, right.report()


def test_a_ragged_row_is_reported_not_shifted():
    result = structured.parse("a,b,c\n1,2,3\n4,5\n", fmt="csv")
    assert [row["a"] for row in result.rows] == ["1"]
    assert len(result.skipped) == 1
    assert "expected 3 cells, got 2" in result.skipped[0]


def test_a_duplicated_header_name_is_fatal():
    with pytest.raises(structured.ParseError) as exc:
        structured.parse("id,name,id\n1,a,2\n", fmt="csv")
    assert "'id'" in str(exc.value)
    assert "ambiguous" in str(exc.value)


def test_an_unnamed_column_is_fatal():
    with pytest.raises(structured.ParseError) as exc:
        structured.parse("id,,name\n1,x,a\n", fmt="csv")
    assert "no name" in str(exc.value)


def test_an_empty_capture_is_fatal():
    with pytest.raises(structured.ParseError) as exc:
        structured.parse("\n\n", fmt="csv")
    assert "no header row" in str(exc.value)


def test_a_byte_order_mark_does_not_rename_the_first_column():
    """Otherwise every binding to `id` fails as `no such field`, for no visible reason."""
    rows = structured.parse("﻿id,name\n1,alpha\n", fmt="csv").rows
    assert rows[0]["id"] == "1"


def test_tsv_does_not_treat_a_quote_as_quoting():
    """A tab cannot appear inside a tsv field, so quotes there are just characters."""
    rows = structured.parse('name\tnote\nalpha\t"quoted" text\n', fmt="tsv").rows
    assert rows[0]["note"] == '"quoted" text'


def test_the_delimiter_is_declared_and_never_sniffed():
    """Read as tsv, a csv is one column - wrong, and wrong loudly rather than plausibly."""
    rows = structured.parse(CSV_FIXTURE.read_text(), fmt="tsv").rows
    assert len(rows[0]) == 1
    assert "detection_id" not in rows[0]


def test_jsonl_is_one_record_per_line_with_nesting_intact():
    rows = structured.parse(JSONL_FIXTURE.read_text(), fmt="jsonl").rows
    assert len(rows) == 3
    assert rows[0]["device.hostname"] == "host-a.example.invalid"
    assert rows[0]["severity"] == 70
    assert rows[0]["quarantined"] is False
    assert rows[2]["indicators.1"] == "T1071.001"
    assert rows[1]["indicators"] == "[]"
    assert rows[2]["severity"] is None


def test_a_bad_line_costs_that_line_and_says_which():
    text = '{"a": 1}\nnot json at all\n{"b": 2}\n'
    result = structured.parse(text, fmt="jsonl")
    assert len(result.rows) == 2
    assert "line 2" in result.skipped[0]


def test_a_jsonl_line_that_is_not_an_object_is_reported():
    result = structured.parse('{"a": 1}\n[1, 2]\n', fmt="jsonl")
    assert len(result.rows) == 1
    assert "line 2 is a list" in result.skipped[0]


def test_records_at_is_refused_for_a_format_that_has_no_inside():
    with pytest.raises(structured.ParseError) as exc:
        structured.parse(CSV_FIXTURE.read_text(), records_at="rows", fmt="csv")
    assert "already a sequence of records" in str(exc.value)


def test_an_unknown_format_is_refused():
    with pytest.raises(structured.ParseError) as exc:
        structured.parse("a,b\n1,2\n", fmt="xml")
    assert "unknown format" in str(exc.value)


def test_the_same_bytes_read_as_two_formats_are_two_tool_calls(tmp_path):
    store = Store(tmp_path / "case.db")
    as_csv = ingest(store, CSV_FIXTURE, tool="edr_export", fmt="csv")
    as_tsv = ingest(store, CSV_FIXTURE, tool="edr_export", fmt="tsv")
    assert as_csv["tool_call_id"] != as_tsv["tool_call_id"]


def test_identical_rows_are_one_record_and_the_ingest_says_so(tmp_path):
    """A count that quietly shrinks reads as a parse failure to whoever checks it."""
    capture = tmp_path / "dupes.csv"
    capture.write_text("id,verdict\n1,clean\n1,clean\n2,clean\n")
    store = Store(tmp_path / "case.db")
    result = ingest(store, capture, tool="edr_export", fmt="csv")
    assert result["records"] == 2
    assert result["duplicates"] == 1


def test_a_delimited_case_replays_to_the_same_head(tmp_path):
    store = Store(tmp_path / "case.db")
    ingest(store, CSV_FIXTURE, tool="edr_export", fmt="csv", kind="detection", host="soc")
    ingest(store, JSONL_FIXTURE, tool="edr_stream", fmt="jsonl", kind="event", host="soc")
    record = store.query_records(kind="detection", where={"detection_id": "D-1002"})[0]
    submit_finding(
        store,
        finding_type="observation",
        claim="One detection was raised on host-b.example.invalid.",
        bindings=[Binding(record["record_id"], "device", "host-b.example.invalid")],
    )
    result = replay(store, ["fixtures"], Store(tmp_path / "replayed.db"))
    assert result.ok, result.report()
    assert result.replayed_head == store.head()


def test_cli_ingests_a_csv_export(tmp_path, capsys):
    from witness.cli import main

    code = main([
        "--store", str(tmp_path / "case.db"),
        "ingest", "--tool", "response", "--source", "edr_export", "--format", "csv",
        "--kind", "detection", "--input", str(CSV_FIXTURE),
    ])
    out = capsys.readouterr().out
    assert code == 0
    assert "records     3 of kind detection" in out


def test_cli_reports_a_header_it_cannot_use(tmp_path, capsys):
    from witness.cli import main

    bad = tmp_path / "bad.csv"
    bad.write_text("id,name,id\n1,a,2\n")
    code = main([
        "--store", str(tmp_path / "case.db"),
        "ingest", "--tool", "response", "--source", "edr_export", "--format", "csv",
        "--input", str(bad),
    ])
    assert code == 1
    assert "ambiguous" in capsys.readouterr().out
