"""What the store holds, counted rather than declared.

A binding names a field. An agent that has to guess a field name guesses one that
reads well and gets refused, which is the right outcome and a wasted turn. These
tests are about the listing that removes the guess - and mostly about the one
property that makes it safe to rely on: it does not lie. Every field it names is
a field the gate accepts on the records it says carry it, and the fraction it
prints is the fraction that really do.
"""

from pathlib import Path

from witness import shape
from witness.collectors import structured
from witness.collectors.volatility import ingest_capture
from witness.store import Store
from witness.verify import Binding, verify

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SYNTHETIC = FIXTURES / "synthetic"


def csv_store(tmp_path, host="soc"):
    store = Store(tmp_path / "case.db")
    structured.ingest_capture(
        store, tool="edr_export", output_path=SYNTHETIC / "detections.csv",
        fmt="csv", kind="detection", host=host,
    )
    return store


def jsonl_store(tmp_path, host="soc"):
    store = Store(tmp_path / "case.db")
    structured.ingest_capture(
        store, tool="edr_stream", output_path=SYNTHETIC / "detections.jsonl",
        fmt="jsonl", kind="event", host=host,
    )
    return store


def from_text(tmp_path, text, name="rows.jsonl", fmt="jsonl"):
    capture = tmp_path / name
    capture.write_text(text)
    store = Store(tmp_path / "case.db")
    structured.ingest_capture(store, tool="t", output_path=capture, fmt=fmt, kind="k")
    return store


def field(described, name):
    return next(f for f in described.fields if f.name == name)


# ------------------------------------------------------------------ the catalogue


def test_kinds_lists_what_the_store_holds(tmp_path):
    store = csv_store(tmp_path)
    ingest_capture(
        store, plugin_name="psscan", output_path=FIXTURES / "wkstn05" / "psscan.txt",
        host="base-wkstn-05",
    )
    found = {item.kind: item for item in shape.kinds(store)}
    assert set(found) == {"detection", "process"}
    assert found["detection"].records == 3
    assert found["process"].records == 57
    assert found["process"].tool_calls == 1


def test_kinds_are_scoped_to_a_host(tmp_path):
    store = csv_store(tmp_path, host="soc")
    assert [item.kind for item in shape.kinds(store, host="soc")] == ["detection"]
    assert shape.kinds(store, host="somewhere-else") == []


def test_an_absent_kind_describes_to_nothing(tmp_path):
    assert shape.describe(csv_store(tmp_path), "not_a_kind") is None


# --------------------------------------------------------------------- the shape


def test_every_field_is_named_once_and_counted(tmp_path):
    described = shape.describe(csv_store(tmp_path), "detection")
    assert described.records == 3
    assert [f.name for f in described.fields] == [
        "account_id", "description", "detection_id",
        "device", "first_seen", "severity", "technique",
    ]
    assert all(f.present == 3 for f in described.fields)


def test_presence_is_a_fraction_because_records_are_ragged(tmp_path):
    """The trap in every export: a field in the listing that not every record has."""
    described = shape.describe(jsonl_store(tmp_path), "event")
    assert described.records == 3
    assert field(described, "detection_id").present == 3
    assert field(described, "indicators.0").present == 2
    assert field(described, "indicators.1").present == 1


def test_a_mixed_type_field_says_both(tmp_path):
    described = shape.describe(jsonl_store(tmp_path), "event")
    assert field(described, "severity").types == ["int", "null"]
    assert field(described, "device.hostname").types == ["text"]
    assert field(described, "quarantined").types == ["bool"]


def test_a_boolean_and_a_one_are_two_values_not_one(tmp_path):
    """The same distinction the gate makes when it refuses 1 against a bool field."""
    store = from_text(tmp_path, '{"flag": true}\n{"flag": 1}\n')
    described = shape.describe(store, "k")
    assert field(described, "flag").distinct == 2
    assert field(described, "flag").types == ["bool", "int"]


def test_examples_lead_with_one_value_of_each_type(tmp_path):
    """Otherwise a column advertises null and never shows one."""
    store = from_text(
        tmp_path,
        "".join(f'{{"seen": "2018-08-30 0{n}:00:00"}}\n' for n in range(5)) + '{"seen": null}\n',
    )
    seen = field(shape.describe(store, "k"), "seen")
    assert seen.types == ["null", "text"]
    assert None in seen.examples
    assert "None" in seen.values


def test_what_is_not_shown_is_counted(tmp_path):
    store = from_text(tmp_path, "".join(f'{{"n": {n}}}\n' for n in range(20)))
    n = field(shape.describe(store, "k"), "n")
    assert n.distinct == 20
    assert len(n.examples) == shape.SAMPLE
    assert n.values.endswith(f"+{20 - shape.SAMPLE} more")


def test_one_long_value_does_not_take_the_whole_line(tmp_path):
    store = from_text(
        tmp_path,
        '{"note": "%s"}\n{"note": "b"}\n{"note": "c"}\n' % ("a" * 400),
    )
    note = field(shape.describe(store, "k"), "note")
    assert note.distinct == 3
    assert "+2 more" in note.values, "the width cap and the sample cap share one count"
    assert len(note.values) < 140


def test_a_padded_identifier_is_rendered_so_it_cannot_read_as_a_number(tmp_path):
    values = field(shape.describe(csv_store(tmp_path), "detection"), "account_id").values
    assert "'00417'" in values


def test_a_hostile_value_cannot_paint_the_listing(tmp_path):
    """Terminal control sequences in evidence are evidence, not instructions."""
    store = from_text(tmp_path, '{"note": "\\u001b[31mred\\u001b[0m and\\na new line"}\n')
    values = field(shape.describe(store, "k"), "note").values
    assert "\x1b" not in values
    assert "\n" not in values


# ------------------------------------------------------------ the listing is true


def test_every_field_named_is_a_field_the_gate_accepts(tmp_path):
    """The whole point. A listing an agent cannot bind against is worse than none."""
    store = jsonl_store(tmp_path)
    described = shape.describe(store, "event")
    records = store.query_records(kind="event")
    for item in described.fields:
        carrying = [r for r in records if item.name in r["fields"]]
        assert len(carrying) == item.present
        for record in carrying:
            verdict = verify(
                store,
                f"{item.name} is what the store says it is.",
                [Binding(record["record_id"], item.name, record["fields"][item.name])],
            )
            assert verdict.accepted, verdict.report()


def test_a_field_missing_from_a_record_is_refused_there(tmp_path):
    """`2/3` is not decoration: binding to the third record fails, and should."""
    store = jsonl_store(tmp_path)
    described = shape.describe(store, "event")
    assert field(described, "indicators.1").present == 1
    without = [
        r for r in store.query_records(kind="event") if "indicators.1" not in r["fields"]
    ]
    assert len(without) == 2
    verdict = verify(
        store, "It had a second indicator.", [Binding(without[0]["record_id"], "indicators.1", "T1105")]
    )
    assert not verdict.accepted
    assert "no field" in verdict.refutation


# -------------------------------------------------------------------------- cli


def test_cli_lists_the_kinds(tmp_path, capsys):
    from witness.cli import main

    store_path = tmp_path / "case.db"
    csv_store(tmp_path)
    code = main(["--store", str(store_path), "fields"])
    out = capsys.readouterr().out
    assert code == 0
    assert "detection" in out
    assert "-- 1 kind(s)" in out


def test_cli_describes_one_kind(tmp_path, capsys):
    from witness.cli import main

    store_path = tmp_path / "case.db"
    csv_store(tmp_path)
    code = main(["--store", str(store_path), "fields", "--kind", "detection"])
    out = capsys.readouterr().out
    assert code == 0
    assert "account_id" in out
    assert "3/3" in out
    assert "-- 7 field(s)" in out


def test_cli_says_what_it_has_when_the_kind_is_wrong(tmp_path, capsys):
    from witness.cli import main

    store_path = tmp_path / "case.db"
    csv_store(tmp_path)
    code = main(["--store", str(store_path), "fields", "--kind", "detections"])
    out = capsys.readouterr().out
    assert code == 1
    assert "this store holds: detection" in out
