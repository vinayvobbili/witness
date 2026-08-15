from witness.store import Store, coerce, sha256_text


def make_store(tmp_path) -> Store:
    return Store(tmp_path / "s.db")


def test_chain_verifies_after_writes(tmp_path):
    store = make_store(tmp_path)
    call = store.add_tool_call(tool="t", argv=["t"], mode="replay", output_text="out")
    store.add_records(call, "process", [{"pid": 1}, {"pid": 2}])
    ok, problems = store.verify_chain()
    assert ok, problems


def test_tool_call_id_is_content_derived_not_time_derived(tmp_path):
    a = Store(tmp_path / "a.db").add_tool_call(tool="t", argv=["t"], mode="replay", output_text="out")
    b = Store(tmp_path / "b.db").add_tool_call(tool="t", argv=["t"], mode="replay", output_text="out")
    assert a == b


def test_reingesting_the_same_output_does_not_duplicate(tmp_path):
    store = make_store(tmp_path)
    call = store.add_tool_call(tool="t", argv=["t"], mode="replay", output_text="out")
    again = store.add_tool_call(tool="t", argv=["t"], mode="replay", output_text="out")
    assert call == again
    first = store.add_records(call, "process", [{"pid": 1}])
    second = store.add_records(call, "process", [{"pid": 1}])
    assert first == second
    assert len(store.query_records(kind="process")) == 1


def test_editing_a_record_breaks_the_chain(tmp_path):
    store = make_store(tmp_path)
    call = store.add_tool_call(tool="t", argv=["t"], mode="replay", output_text="out")
    store.add_records(call, "process", [{"pid": 1, "image_file_name": "evil.exe"}])

    # Tamper directly in the chain, the way someone rewriting history would.
    payload = store.db.execute("SELECT payload FROM chain WHERE kind='record'").fetchone()["payload"]
    store.db.execute(
        "UPDATE chain SET payload = ? WHERE kind='record'",
        (payload.replace("evil.exe", "notepad.exe"),),
    )
    store.db.commit()

    ok, problems = store.verify_chain()
    assert not ok
    assert any("payload does not match its hash" in p for p in problems)


def test_records_cannot_attach_to_an_unknown_tool_call(tmp_path):
    store = make_store(tmp_path)
    try:
        store.add_records("deadbeef1234", "process", [{"pid": 1}])
    except ValueError as exc:
        assert "no such tool call" in str(exc)
    else:
        raise AssertionError("expected a ValueError")


def test_canonical_hash_is_key_order_independent(tmp_path):
    store = make_store(tmp_path)
    call = store.add_tool_call(tool="t", argv=["t"], mode="replay", output_text="out")
    ids = store.add_records(call, "process", [{"pid": 1, "ppid": 2}])
    stored = store.get_record(ids[0])
    assert stored["content_hash"] == sha256_text('{"pid":1,"ppid":2}')


# `coerce` is what lets a claim written as text meet a value parsed as a number.
# Its tolerances are the gate's tolerances, so each one is a decision, not a
# convenience - and the padding rule is the one that keeps identifiers apart from
# the numbers they resemble.


def test_coerce_reads_a_number_written_as_text():
    assert coerce("3720") == 3720
    assert coerce("-12") == -12
    assert coerce("  3720  ") == 3720
    assert coerce("0xe88") == 0xE88


def test_coerce_leaves_a_padded_number_alone():
    """00417 is an account, 007 is an agent, and neither is arithmetic."""
    assert coerce("00417") == "00417"
    assert coerce("007") == "007"
    assert coerce("-007") == "-007"
    assert coerce("0") == 0, "a lone zero is the number zero, not padding"


def test_a_padded_identifier_and_its_number_do_not_meet():
    assert coerce("00417") != coerce(417)
    assert coerce("00417") == coerce("00417")


def test_coerce_keeps_hex_padding_readable():
    """Tools print offsets with leading zeroes and mean the same offset."""
    assert coerce("0x0e88") == 0xE88
