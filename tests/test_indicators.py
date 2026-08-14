"""Slice 3: the indicator oracle, and what a domain has to survive to be a finding.

The graded find-evil run met fifteen suspicious external domains in one memory
image and reported one. It got that right by reasoning about them in prose. The
question here is which parts of that reasoning are checkable, and what happens
to the parts that are not.
"""

from pathlib import Path

import pytest

from witness.collectors import decode, indicators, rawstrings
from witness.collectors.volatility import ingest_capture
from witness.falsify import REFUTED, UNAVAILABLE, falsify
from witness.store import Store
from witness.verify import Binding, submit_finding

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

EMBEDDED_C2 = "aaa.stage.9231829.extranet.wagonwheelgifts.com"


@pytest.fixture
def wkstn05(tmp_path):
    """Carved strings, unwrapped payloads, extracted indicators - the full chain."""
    store = Store(tmp_path / "wkstn05.db")
    rawstrings.ingest_capture(
        store,
        output_path=FIXTURES / "wkstn05" / "strings.txt",
        host="base-wkstn-05",
        evidence_path="base-wkstn-05-memory.img",
    )
    decode.unwrap(store, host="base-wkstn-05")
    indicators.extract(store, host="base-wkstn-05")
    return store


def indicator_for(store, value, host="base-wkstn-05"):
    hits = store.query_records(kind="indicator", host=host, where={"value": value})
    assert hits, f"no indicator record for {value}"
    return hits[0]["record_id"]


def domains(store, executed=None):
    return {
        r["fields"]["value"]
        for r in store.query_records(kind="indicator")
        if r["fields"]["type"] == "domain"
        and (executed is None or r["fields"]["execution_context"] is executed)
    }


# --------------------------------------------------------------- extraction shape


def test_a_dotted_token_is_not_a_domain(wkstn05):
    """`IO.MemoryStream` and a name cut mid-carve both look like hostnames."""
    found = domains(wkstn05)
    assert "io.memorystream" not in found
    assert "base-mail.shiel" not in found
    assert "base-mail.shieldbase.lan" in found, "a real internal name still extracts"


def test_what_the_tld_filter_turned_away_is_reported(tmp_path):
    """A filter that drops evidence says what it dropped, or the count lies."""
    store = Store(tmp_path / "declined.db")
    rawstrings.ingest_capture(store, output_path=FIXTURES / "wkstn05" / "strings.txt", host="h")
    decode.unwrap(store, host="h")
    result = indicators.extract(store, host="h")
    assert "memorystream" in result["declined_suffixes"]
    assert result["tld_list"].startswith("Version ")


def test_defanged_indicators_normalise_to_the_same_value():
    plain = indicators.extract_from_text("contact http://evil.example.com/x now")
    fanged = indicators.extract_from_text("contact hxxp://evil[.]example[.]com/x now")
    assert {i["value"] for i in plain if i["type"] == "domain"} == {"evil.example.com"}
    assert {i["value"] for i in fanged if i["type"] == "domain"} == {"evil.example.com"}
    assert all(i["defanged"] for i in fanged)


def test_the_host_inside_a_url_is_also_a_domain():
    found = indicators.extract_from_text("http://www.venetodns.trade/dtsbze/x.png")
    assert {i["type"] for i in found} >= {"url", "domain"}
    assert any(i["value"] == "www.venetodns.trade" for i in found)


# ------------------------------------------------- carved bytes versus something that ran


def test_only_the_decoded_payload_domain_is_in_an_execution_context(wkstn05):
    """One domain on this host came out of something that ran. Six were lying in RAM."""
    assert domains(wkstn05, executed=True) == {EMBEDDED_C2}
    assert "www.venetodns.trade" in domains(wkstn05, executed=False)


def test_the_executed_domain_is_admitted(wkstn05):
    verdict, finding_id = submit_finding(
        wkstn05,
        finding_type="malicious_domain",
        claim=f"The in-memory stager beacons to {EMBEDDED_C2}.",
        bindings=[Binding(indicator_for(wkstn05, EMBEDDED_C2), "value", EMBEDDED_C2)],
        subject={"domain": EMBEDDED_C2},
    )
    assert verdict.accepted, verdict.report()
    assert finding_id


def test_a_domain_only_seen_in_a_carve_is_unproven_not_confirmed(wkstn05):
    """The honest verdict on a domain sitting in a strings dump.

    Not refuted - it may well be the C2. But nothing in this evidence ties it to
    anything that executed, and "found in the image" is not that tie.
    """
    domain = "www.venetodns.trade"
    verdict, finding_id = submit_finding(
        wkstn05,
        finding_type="malicious_domain",
        claim=f"The host beaconed to external C2 {domain}.",
        bindings=[Binding(indicator_for(wkstn05, domain), "value", domain)],
        subject={"domain": domain},
    )
    assert not verdict.accepted
    assert finding_id is None
    outcomes = {c.name: c.outcome for c in verdict.checks}
    assert outcomes["domain_appears_in_evidence"] == "corroborated"
    assert outcomes["domain_appears_in_execution_context"] == UNAVAILABLE
    assert "Attribute it" in verdict.report()


def test_an_internal_name_is_refuted(wkstn05):
    """The corporate mail server looks exactly as suspicious as a C2 in a dump."""
    domain = "base-mail.shieldbase.lan"
    verdict, finding_id = submit_finding(
        wkstn05,
        finding_type="malicious_domain",
        claim=f"{domain} is attacker infrastructure.",
        bindings=[Binding(indicator_for(wkstn05, domain), "value", domain)],
        subject={"domain": domain},
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "is_internal_namespace" in verdict.report()


def test_the_noise_domains_all_stop_at_the_same_gate(wkstn05):
    """Whatever else they are, none of them is tied to execution on this host."""
    for domain in domains(wkstn05, executed=False):
        result = falsify(wkstn05, "malicious_domain", {"domain": domain}, host="base-wkstn-05")
        assert not result.passed, f"{domain} should not pass"


# ------------------------------------------------------------------ host scoping


def test_one_host_does_not_supply_another_hosts_indicators(tmp_path):
    store = Store(tmp_path / "two.db")
    rawstrings.ingest_capture(
        store, output_path=FIXTURES / "wkstn05" / "strings.txt", host="base-wkstn-05"
    )
    decode.unwrap(store, host="base-wkstn-05")
    indicators.extract(store, host="base-wkstn-05")

    ingest_capture(
        store,
        plugin_name="netscan",
        output_path=FIXTURES / "wkstn01" / "netscan.txt",
        host="base-wkstn-01",
    )
    indicators.extract(store, host="base-wkstn-01")

    # Bind to base-wkstn-05's indicator while declaring the finding is about
    # base-wkstn-01. The prose in a claim is not checkable; the declaration is.
    verdict, finding_id = submit_finding(
        store,
        finding_type="malicious_domain",
        claim=f"base-wkstn-01 beaconed to {EMBEDDED_C2}.",
        bindings=[Binding(indicator_for(store, EMBEDDED_C2), "value", EMBEDDED_C2)],
        subject={"domain": EMBEDDED_C2},
        host="base-wkstn-01",
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "evidence comes from 'base-wkstn-05'" in verdict.report()

    # And the same claim scoped to base-wkstn-01's own evidence finds nothing.
    assert (
        falsify(store, "malicious_domain", {"domain": EMBEDDED_C2}, host="base-wkstn-01")
        .results[1]
        .outcome
        == REFUTED
    )


def test_a_finding_may_not_straddle_two_hosts(tmp_path):
    store = Store(tmp_path / "straddle.db")
    rawstrings.ingest_capture(
        store, output_path=FIXTURES / "wkstn05" / "strings.txt", host="base-wkstn-05"
    )
    decode.unwrap(store, host="base-wkstn-05")
    indicators.extract(store, host="base-wkstn-05")
    ingest_capture(
        store,
        plugin_name="netscan",
        output_path=FIXTURES / "wkstn01" / "netscan.txt",
        host="base-wkstn-01",
    )
    other = store.query_records(kind="network_endpoint", host="base-wkstn-01")[0]

    verdict, finding_id = submit_finding(
        store,
        finding_type="observation",
        claim="Two machines, one finding.",
        bindings=[
            Binding(indicator_for(store, EMBEDDED_C2), "value", EMBEDDED_C2),
            Binding(other["record_id"], "pid", other["fields"]["pid"]),
        ],
    )
    assert not verdict.accepted
    assert finding_id is None
    assert "more than one host" in verdict.report()


def test_a_near_miss_is_named_rather_than_tolerated(wkstn05):
    """A registrable parent is an inference from the name in evidence, not the name."""
    result = falsify(
        wkstn05, "malicious_domain", {"domain": "wagonwheelgifts.com"}, host="base-wkstn-05"
    )
    assert not result.passed
    detail = " ".join(r.detail for r in result.results)
    assert EMBEDDED_C2 in detail, "the refusal has to say what evidence does hold"


# --------------------------------------------------------------- encoded payloads


def test_a_payload_claim_must_name_a_payload_that_was_decoded(wkstn05):
    payload = wkstn05.query_records(kind="decoded_payload")[0]
    blob_sha = payload["fields"]["blob_sha256"]
    verdict, finding_id = submit_finding(
        wkstn05,
        finding_type="encoded_payload",
        claim="A gzip-compressed base64 PowerShell payload ran on this host.",
        bindings=[Binding(payload["record_id"], "blob_sha256", blob_sha)],
        subject={"blob_sha256": blob_sha},
    )
    assert verdict.accepted, verdict.report()
    assert finding_id


def test_a_claim_about_a_truncated_duplicate_capture_is_refuted(wkstn05):
    """Superseded prefix captures were never decoded, so nothing is known about them."""
    superseded = [
        r
        for r in wkstn05.query_records(kind="encoded_blob")
        if r["fields"]["superseded_by"]
    ]
    assert superseded, "fixture should contain prefix captures"
    blob = superseded[0]
    blob_sha = blob["fields"]["blob_sha256"]

    verdict, finding_id = submit_finding(
        wkstn05,
        finding_type="encoded_payload",
        claim="This encoded blob is a PowerShell stager.",
        bindings=[Binding(blob["record_id"], "blob_sha256", blob_sha)],
        subject={"blob_sha256": blob_sha},
    )
    assert all(r.ok for r in verdict.results), "gate 1 passes - the blob record is real"
    assert not verdict.accepted
    assert finding_id is None
