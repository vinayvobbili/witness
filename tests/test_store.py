from witness.store import Store, sha256_text


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
