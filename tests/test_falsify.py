"""Slice 2: the falsification matrix.

Gate 1 stops an agent mis-stating what a tool said. These tests are about the
harder failure - quoting the evidence perfectly and drawing the wrong conclusion
from it. Both cases here are real calls from the graded base-wkstn-01 run, where
the scary reading was correct about the data and wrong about the world.
"""

from pathlib import Path

import pytest

from witness.collectors.volatility import ingest_capture
from witness.falsify import CORROBORATED, REFUTED, UNAVAILABLE, falsify
from witness.store import Store
from witness.verify import Binding, revalidate, submit_finding

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def ingest(store, host, folder, tool, name=None):
    return ingest_capture(
        store,
        plugin_name=tool,
        output_path=FIXTURES / folder / f"{name or tool}.txt",
        host=host,
        evidence_path=f"{host}-memory.img",
    )


@pytest.fixture
def wkstn01(tmp_path):
    """The clean baseline host: netscan ingested, malfind ingested and empty."""
    store = Store(tmp_path / "wkstn01.db")
    ingest(store, "base-wkstn-01", "wkstn01", "netscan")
    ingest(store, "base-wkstn-01", "wkstn01", "malfind")
    return store


@pytest.fixture
def wkstn01_no_malfind(tmp_path):
    store = Store(tmp_path / "wkstn01b.db")
    ingest(store, "base-wkstn-01", "wkstn01", "netscan")
    return store


def netscan_record(store, **criteria):
    hits = store.query_records(kind="network_endpoint", where=criteria)
    assert hits, f"no netscan record matching {criteria}"
    return hits[0]["record_id"]


# ------------------------------------------------------- the malfind retraction


def test_malfind_ran_and_found_nothing_refutes_injection(wkstn01):
    """The base-wkstn-01 call: 'injected svchost' dies because malfind is empty."""
    assert wkstn01.query_records(kind="injection_hit") == []

    record = netscan_record(wkstn01, pid=2332)
    verdict, finding_id = submit_finding(
        wkstn01,
        finding_type="process_injection",
        claim="svchost.exe (2332) contains injected code.",
        bindings=[Binding(record, "pid", 2332)],
        subject={"pid": 2332},
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "returned no injection_hit row" in verdict.report()
    assert wkstn01.list_findings() == []


def test_a_tool_that_never_ran_is_a_gap_not_a_pass(wkstn01_no_malfind):
    """The distinction the whole matrix rests on."""
    record = netscan_record(wkstn01_no_malfind, pid=2332)
    verdict, finding_id = submit_finding(
        wkstn01_no_malfind,
        finding_type="process_injection",
        claim="svchost.exe (2332) contains injected code.",
        bindings=[Binding(record, "pid", 2332)],
        subject={"pid": 2332},
    )
    assert not verdict.accepted
    assert finding_id is None
    assert [c.outcome for c in verdict.checks] == [UNAVAILABLE]
    assert "windows.malfind has not been run" in verdict.report()


def test_malfind_with_hits_corroborates(tmp_path):
    """Same claim, evidence present. Fixture is synthetic - see fixtures/synthetic."""
    store = Store(tmp_path / "s.db")
    ingest(store, "base-wkstn-01", "wkstn01", "netscan")
    ingest(store, "base-wkstn-01", "synthetic", "malfind", name="malfind_hits")

    record = netscan_record(store, pid=2332)
    verdict, finding_id = submit_finding(
        store,
        finding_type="process_injection",
        claim="svchost.exe (2332) contains injected code.",
        bindings=[Binding(record, "pid", 2332)],
        subject={"pid": 2332},
    )
    assert verdict.accepted, verdict.report()
    assert finding_id
    assert [c.outcome for c in verdict.checks] == [CORROBORATED]


# --------------------------------------------------------- the proxy false call


def test_internal_peer_refutes_external_c2(wkstn01):
    """The other base-wkstn-01 call: 172.16.4.10:8080 is proxy egress, not C2.

    Every binding here verifies. The connection is real. The conclusion is not.
    """
    record = netscan_record(wkstn01, foreign_addr="172.16.4.10", foreign_port=8080)
    verdict, finding_id = submit_finding(
        wkstn01,
        finding_type="external_c2",
        claim="svchost.exe beaconed to external C2 at 172.16.4.10:8080.",
        bindings=[
            Binding(record, "foreign_addr", "172.16.4.10"),
            Binding(record, "foreign_port", 8080),
        ],
        subject={"foreign_addr": "172.16.4.10"},
    )
    assert all(r.ok for r in verdict.results), "gate 1 should pass - the record says this"
    assert not verdict.accepted, "gate 2 should kill it - the peer is RFC1918"
    assert finding_id is None
    assert "is_public_ip" in verdict.report()


def test_a_routable_peer_passes_the_predicate(wkstn01):
    external = wkstn01.query_records(kind="network_endpoint", where={"foreign_addr": "8.8.8.8"})
    assert external == [], "sanity: this host has no public peers"
    assert falsify(wkstn01, "external_c2", {"foreign_addr": "8.8.8.8"}).passed
    assert not falsify(wkstn01, "external_c2", {"foreign_addr": "172.16.4.10"}).passed


# --------------------------------------------------------------- matrix hygiene


def test_an_unregistered_finding_type_is_refused(wkstn01):
    record = netscan_record(wkstn01, pid=2332)
    verdict, finding_id = submit_finding(
        wkstn01,
        finding_type="definitely_evil",
        claim="Trust me on this one.",
        bindings=[Binding(record, "pid", 2332)],
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "no falsification rule registered" in verdict.report()


def test_observation_is_an_escape_hatch_not_a_bypass(wkstn01):
    record = netscan_record(wkstn01, pid=2332)
    verdict, finding_id = submit_finding(
        wkstn01,
        finding_type="observation",
        claim="PID 2332 held a connection to 172.16.4.10:8080.",
        bindings=[Binding(record, "foreign_addr", "172.16.4.10")],
    )
    assert verdict.accepted, verdict.report()

    # Still fully bound: an observation with a wrong value is refused like anything else.
    bad, bad_id = submit_finding(
        wkstn01,
        finding_type="observation",
        claim="PID 2332 held a connection to 9.9.9.9.",
        bindings=[Binding(record, "foreign_addr", "9.9.9.9")],
    )
    assert not bad.accepted
    assert bad_id is None


def test_subject_must_be_proved_by_a_binding(wkstn01):
    """Otherwise the checks would run against a process nobody cited."""
    record = netscan_record(wkstn01, pid=2332)
    verdict, finding_id = submit_finding(
        wkstn01,
        finding_type="process_injection",
        claim="svchost.exe (2332) contains injected code.",
        bindings=[Binding(record, "pid", 2332)],
        subject={"pid": 4},  # a PID with no malfind coverage, smuggled in
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "is not proved by any binding" in verdict.report()


def test_missing_subject_key_is_refused(wkstn01):
    record = netscan_record(wkstn01, pid=2332)
    verdict, _ = submit_finding(
        wkstn01,
        finding_type="process_injection",
        claim="Something is injected.",
        bindings=[Binding(record, "pid", 2332)],
    )
    assert not verdict.accepted
    assert "requires subject key(s): pid" in verdict.report()


def test_checks_do_not_cross_hosts(tmp_path):
    """wkstn-05's malfind must not corroborate a claim about wkstn-01."""
    store = Store(tmp_path / "two.db")
    ingest(store, "base-wkstn-01", "wkstn01", "netscan")
    ingest(store, "base-wkstn-05", "synthetic", "malfind", name="malfind_hits")

    record = netscan_record(store, pid=2332)
    verdict, finding_id = submit_finding(
        store,
        finding_type="process_injection",
        claim="svchost.exe (2332) on base-wkstn-01 contains injected code.",
        bindings=[Binding(record, "pid", 2332)],
        subject={"pid": 2332},
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "has not been run on base-wkstn-01" in verdict.report()


# ------------------------------------------------------------- retroactive pass


def test_new_evidence_retracts_an_earlier_finding(tmp_path):
    """A finding admitted before the refuting tool landed does not stay admitted."""
    store = Store(tmp_path / "r.db")
    ingest(store, "base-wkstn-01", "wkstn01", "netscan")
    ingest(store, "base-wkstn-01", "synthetic", "malfind", name="malfind_hits")

    record = netscan_record(store, pid=2332)
    _, finding_id = submit_finding(
        store,
        finding_type="process_injection",
        claim="svchost.exe (2332) contains injected code.",
        bindings=[Binding(record, "pid", 2332)],
        subject={"pid": 2332},
    )
    assert finding_id
    assert revalidate(store) == []

    # A fuller malfind run over the same host comes back empty for this PID.
    store.db.execute("DELETE FROM records WHERE kind = 'injection_hit'")
    store.db.commit()

    retracted = revalidate(store)
    assert [f for f, _ in retracted] == [finding_id]

    findings = store.list_findings()
    assert findings[0]["status"] == "retracted"
    assert "refuted on revalidation" in findings[0]["retraction_reason"]
    assert store.list_findings(include_retracted=False) == []


def test_a_retraction_does_not_delete_the_finding(tmp_path):
    store = Store(tmp_path / "r2.db")
    ingest(store, "base-wkstn-01", "wkstn01", "netscan")
    record = netscan_record(store, pid=2332)
    _, finding_id = submit_finding(
        store,
        finding_type="observation",
        claim="PID 2332 held a connection to 172.16.4.10:8080.",
        bindings=[Binding(record, "foreign_addr", "172.16.4.10")],
    )
    store.add_retraction(finding_id=finding_id, reason="analyst withdrew it")

    findings = store.list_findings()
    assert len(findings) == 1
    assert findings[0]["claim"].startswith("PID 2332 held")
    ok, problems = store.verify_chain()
    assert ok, problems


# ------------------------------------------------------------- rejection record


def test_rejected_claims_are_logged_with_their_refutation(wkstn01):
    record = netscan_record(wkstn01, foreign_addr="172.16.4.10", foreign_port=8080)
    submit_finding(
        wkstn01,
        finding_type="external_c2",
        claim="svchost.exe beaconed to external C2 at 172.16.4.10:8080.",
        bindings=[Binding(record, "foreign_addr", "172.16.4.10")],
        subject={"foreign_addr": "172.16.4.10"},
    )
    rejections = wkstn01.list_rejections()
    assert len(rejections) == 1
    assert "peer_is_routable" in rejections[0]["reason"]
    ok, _ = wkstn01.verify_chain()
    assert ok
