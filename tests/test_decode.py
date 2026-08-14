"""Slice 3: unwrapping encoded payloads, deterministically.

`H4sIAAAA...` in a command line is where an agent's confidence usually outruns
its evidence - "a gzipped PowerShell stager, probably Empire, beaconing to some
C2" is three guesses about bytes that simply decode. These tests run against the
real carved strings from the SANS base-wkstn-05 image.
"""

from pathlib import Path

import pytest

from witness.collectors import decode, rawstrings
from witness.store import Store

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def carved(tmp_path):
    store = Store(tmp_path / "strings.db")
    rawstrings.ingest_capture(
        store,
        output_path=FIXTURES / "wkstn05" / "strings.txt",
        host="base-wkstn-05",
        evidence_path="base-wkstn-05-memory.img",
    )
    return store


def payloads(store, stage=None):
    rows = [r["fields"] for r in store.query_records(kind="decoded_payload")]
    return [p for p in rows if stage is None or p["stage"] == stage]


# ------------------------------------------------------------- the same blob, seven times


def test_repeated_captures_of_one_blob_decode_once(carved):
    """A strings pass yields the same command line at several truncation lengths."""
    result = decode.unwrap(carved, host="base-wkstn-05")
    assert result["command_lines"] == 7, "seven carved copies of the command line"
    assert result["superseded"] >= 3, "shorter captures are prefixes of a longer one"
    assert len(payloads(carved, stage=1)) == 1, "one payload, not one per capture"

    blobs = [r["fields"] for r in carved.query_records(kind="encoded_blob")]
    superseded = [b for b in blobs if b["superseded_by"]]
    assert superseded, "the prefix captures stay in the store"
    assert all(b["superseded_by"] != b["blob_sha256"] for b in superseded)


def test_a_carved_line_running_into_prose_does_not_corrupt_the_blob(carved):
    """Two of these lines are cut mid-base64 and run on into unrelated text.

    A character class loose enough to swallow the space would splice those words
    into the payload and inflate something that was never in the image.
    """
    decode.unwrap(carved, host="base-wkstn-05")
    stage1 = payloads(carved, stage=1)[0]
    assert stage1["container"] == "gzip"
    assert stage1["content_type"] == "text"
    assert stage1["text"].startswith("Set-StrictMode -Version 2")


def test_a_truncated_stream_keeps_what_inflated_and_says_so(carved):
    """Carved payloads are cut short. Partial is useful; silently partial is not."""
    decode.unwrap(carved, host="base-wkstn-05")
    stage1 = payloads(carved, stage=1)[0]
    assert stage1["truncated"] is True
    assert stage1["decoded_bytes"] > 2000


# ----------------------------------------------------------------- the second stage


def test_the_second_stage_is_unwrapped_too(carved):
    """The stager carries its own base64 payload, which carries the C2 host."""
    result = decode.unwrap(carved, host="base-wkstn-05")
    assert result["stages"] == 2

    stage2 = payloads(carved, stage=2)
    assert len(stage2) == 1
    assert stage2[0]["content_type"] == "binary", "raw shellcode, not text"
    assert "wagonwheelgifts.com" in stage2[0]["text"]


def test_the_embedded_host_is_not_in_the_plaintext_evidence(carved):
    """It is only reachable by decoding - which is the point of decoding."""
    for record in carved.query_records(kind="string_hit"):
        assert "wagonwheelgifts" not in record["fields"]["text"].lower()


# ------------------------------------------------------------------- provenance


def test_a_decoded_payload_walks_back_to_the_capture(carved):
    decode.unwrap(carved, host="base-wkstn-05")
    record = carved.query_records(kind="decoded_payload")[0]
    trail = [call["tool"] for call in carved.provenance(record["record_id"])]
    assert trail == ["decode.unwrap", "strings"], "newest first, back to the capture"


def test_derived_calls_name_the_records_they_read(carved):
    result = decode.unwrap(carved, host="base-wkstn-05")
    call = carved.get_tool_call(result["tool_call_id"])
    assert call["mode"] == "derived"
    assert call["derived_from"], "a derived call has to say what it derived from"


# ------------------------------------------------------------------------ hygiene


def test_decoding_twice_does_not_duplicate_the_evidence(carved):
    first = decode.unwrap(carved, host="base-wkstn-05")
    before = len(carved.query_records(kind="decoded_payload"))
    second = decode.unwrap(carved, host="base-wkstn-05")
    assert second["tool_call_id"] == first["tool_call_id"]
    assert len(carved.query_records(kind="decoded_payload")) == before
    ok, problems = carved.verify_chain()
    assert ok, problems


def test_one_tool_call_may_emit_several_record_kinds(carved):
    """The analyser writes command lines, blobs and payloads from a single run."""
    result = decode.unwrap(carved, host="base-wkstn-05")
    kinds = {
        r["kind"]
        for r in carved.query_records()
        if r["tool_call_id"] == result["tool_call_id"]
    }
    assert kinds == {"command_line", "encoded_blob", "decoded_payload"}
    ids = [r["record_id"] for r in carved.query_records()]
    assert len(ids) == len(set(ids)), "record ids must not collide across kinds"


def test_nothing_to_decode_is_an_error_not_an_empty_pass(tmp_path):
    store = Store(tmp_path / "empty.db")
    with pytest.raises(ValueError, match="nothing to decode"):
        decode.unwrap(store, host="base-wkstn-05")
