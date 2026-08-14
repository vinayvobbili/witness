"""The slice 1 thesis, as tests.

A finding reaches the ledger only if every field it cites really says what it
claims. These run against real Volatility output captured from the SANS
base-wkstn-05 memory image.
"""

from pathlib import Path

import pytest

from witness.collectors.volatility import ingest_capture
from witness.store import Store
from witness.verify import Binding, submit_finding, verify

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "wkstn05"


@pytest.fixture
def store(tmp_path):
    store = Store(tmp_path / "wkstn05.db")
    ingest_capture(
        store,
        plugin_name="psscan",
        output_path=FIXTURES / "psscan.txt",
        host="base-wkstn-05",
        evidence_path="base-wkstn-05-memory.img",
    )
    ingest_capture(
        store,
        plugin_name="netscan",
        output_path=FIXTURES / "netscan.txt",
        host="base-wkstn-05",
        evidence_path="base-wkstn-05-memory.img",
    )
    return store


def record_for_pid(store: Store, pid: int) -> str:
    matches = [r for r in store.query_records(kind="process") if r["fields"]["pid"] == pid]
    assert len(matches) == 1, f"expected exactly one process record for pid {pid}"
    return matches[0]["record_id"]


def test_the_real_kill_chain_is_accepted(store):
    """WmiPrvSE -> powershell -> powershell -> rundll32, every link cited."""
    bindings = [
        Binding(record_for_pid(store, 2676), "image_file_name", "WmiPrvSE.exe"),
        Binding(record_for_pid(store, 3920), "ppid", 2676),
        Binding(record_for_pid(store, 1332), "ppid", 3920),
        Binding(record_for_pid(store, 3720), "ppid", 1332),
        Binding(record_for_pid(store, 3720), "pid", 3720),
        Binding(record_for_pid(store, 3720), "image_file_name", "rundll32.exe"),
    ]
    verdict, finding_id = submit_finding(
        store,
        finding_type="suspicious_process_chain",
        claim="WmiPrvSE.exe (2676) spawned powershell.exe (3920), which spawned "
        "powershell.exe (1332), which spawned rundll32.exe (3720).",
        bindings=bindings,
        subject={"pid": 3720},
    )
    assert verdict.accepted, verdict.report()
    assert finding_id
    assert len(store.list_findings()) == 1


def test_a_transposed_pid_is_rejected(store):
    """The exact class of error find-evil was built to catch."""
    verdict, finding_id = submit_finding(
        store,
        finding_type="suspicious_process_chain",
        claim="rundll32.exe (3720) was spawned by powershell.exe (1233).",
        bindings=[Binding(record_for_pid(store, 3720), "ppid", 1233)],
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "record says 1332, claim asserts 1233" in verdict.report()
    assert store.list_findings() == []


def test_a_plausible_but_unsupported_claim_is_rejected(store):
    """External C2 is the tempting call here. netscan does not show one."""
    external = [
        r for r in store.query_records(kind="network_endpoint")
        if r["fields"]["foreign_addr"] == "185.220.101.5"
    ]
    assert external == []

    verdict, finding_id = submit_finding(
        store,
        finding_type="external_c2",
        claim="The host beaconed to external C2 185.220.101.5.",
        bindings=[Binding("nonexistent#0001", "foreign_addr", "185.220.101.5")],
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "no such record in the store" in verdict.report()


def test_a_claim_with_no_bindings_is_rejected(store):
    verdict, finding_id = submit_finding(
        store,
        finding_type="observation",
        claim="This host is compromised.",
        bindings=[],
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "must cite at least one record field" in verdict.report()


def test_citing_a_real_record_but_the_wrong_field_value_is_rejected(store):
    """Mulder-style provenance would pass this: the tool call is real."""
    verdict, _ = submit_finding(
        store,
        finding_type="process_present",
        claim="PID 2676 is malware.exe.",
        bindings=[Binding(record_for_pid(store, 2676), "image_file_name", "malware.exe")],
    )
    assert not verdict.accepted
    assert "record says 'WmiPrvSE.exe'" in verdict.report()


def test_truncated_image_name_is_rejected_with_a_usable_hint(store):
    verdict, _ = submit_finding(
        store,
        finding_type="process_present",
        claim="subject_srv.exe was running as PID 3548.",
        bindings=[Binding(record_for_pid(store, 3548), "image_file_name", "subject_srv.exe")],
    )
    assert not verdict.accepted
    assert "truncated this field at 14 characters" in verdict.report()


def test_case_difference_is_accepted_but_recorded(store):
    verdict, finding_id = submit_finding(
        store,
        finding_type="process_present",
        claim="Sysmon64.exe was running as PID 1892.",
        bindings=[
            Binding(record_for_pid(store, 1892), "image_file_name", "Sysmon64.exe"),
            Binding(record_for_pid(store, 1892), "pid", 1892),
        ],
        subject={"pid": 1892},
    )
    assert verdict.accepted
    notes = store.list_findings()[0]["notes"]
    assert any("case-normalised" in note for note in notes)


def test_hex_offsets_compare_correctly_however_they_are_written(store):
    record_id = record_for_pid(store, 2676)
    assert verify(store, "offset", [Binding(record_id, "offset", "0x71cfb00")]).accepted
    assert verify(store, "offset", [Binding(record_id, "offset", "0x71CFB00")]).accepted
    assert verify(store, "offset", [Binding(record_id, "offset", 0x71CFB00)]).accepted
    assert not verify(store, "offset", [Binding(record_id, "offset", "0x71cfb01")]).accepted


def test_a_broken_chain_blocks_every_submission(store):
    row = store.db.execute(
        "SELECT seq, payload FROM chain WHERE kind='record' AND payload LIKE '%WmiPrvSE.exe%' LIMIT 1"
    ).fetchone()
    assert row is not None
    store.db.execute(
        "UPDATE chain SET payload = ? WHERE seq = ?",
        (row["payload"].replace("WmiPrvSE.exe", "notepad.exe"), row["seq"]),
    )
    store.db.commit()

    verdict, finding_id = submit_finding(
        store,
        finding_type="process_present",
        claim="WmiPrvSE.exe was running as PID 2676.",
        bindings=[Binding(record_for_pid(store, 2676), "image_file_name", "WmiPrvSE.exe")],
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "audit chain is broken" in verdict.report()
