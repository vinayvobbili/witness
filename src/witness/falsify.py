"""The second gate: try to disprove a finding before admitting it.

Slice 1 asks "does the cited record really say this?". That stops mis-statement,
not over-reading. A parent PID can be quoted perfectly and the conclusion drawn
from it still be wrong.

So every finding type declares, up front, what evidence would refute it. The
checks are queries and predicates, not a second language model - a model can be
argued out of a correct refutation, an empty result set cannot.

Three outcomes, and the third is the one that matters:

  corroborated  the refuting evidence was looked for and is not there
  refuted       the tool ran and shows the opposite - the claim dies
  unavailable   the tool that would settle it was never run

"unavailable" is not a pass. A claim nobody tried to disprove is not admitted;
the agent is told which tool to run first.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Callable

from .store import Store

CORROBORATED = "corroborated"
REFUTED = "refuted"
UNAVAILABLE = "unavailable"


# ------------------------------------------------------------------ predicates


def _is_public_ip(value: Any) -> bool | None:
    """True for a routable address. None when the value is not an address."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


# Namespaces that are reserved, or reserved by convention, for names that never
# leave the estate. A host under one of them is not attacker infrastructure on
# the internet, whatever else it may be - which is the deterministic answer to
# an agent that reports the corporate mail server as a suspicious external
# domain because it saw it in a memory dump.
_INTERNAL_SUFFIXES = (
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
    ".corp",
    ".internal",
    ".intranet",
    ".home.arpa",
    ".in-addr.arpa",
    ".test",
    ".invalid",
    ".example",
)


def _is_internal_namespace(value: Any) -> bool | None:
    """True for a name that cannot resolve on the public internet."""
    name = str(value).strip().lower().rstrip(".")
    if not name:
        return None
    if "." not in name:
        return True  # a single-label name is only meaningful inside a search domain
    return name.endswith(_INTERNAL_SUFFIXES)


PREDICATES: dict[str, Callable[[Any], bool | None]] = {
    "is_public_ip": _is_public_ip,
    "is_internal_namespace": _is_internal_namespace,
}


# -------------------------------------------------------------------- hints
#
# A refusal is only useful if it tells the agent what to do next. A hint reads
# the store and turns "not found" into "not found, but here is what is".


def _related_indicator_values(store: Store, subject: dict, host: str | None) -> str:
    """Name the indicators actually in evidence that are related to this one."""
    claimed = str(next(iter(subject.values()), "")).strip().lower()
    if not claimed:
        return ""
    values = {
        str(record["fields"].get("value", "")).lower()
        for record in store.query_records(kind="indicator", host=host)
    }
    related = sorted(
        value
        for value in values
        if value and value != claimed and (value.endswith("." + claimed) or claimed.endswith("." + value))
    )
    if not related:
        return ""
    shown = ", ".join(related[:5])
    more = f" (+{len(related) - 5} more)" if len(related) > 5 else ""
    return (
        f" Evidence does contain {shown}{more}."
        " Bind to the name the evidence holds, or say why the parent domain follows from it."
    )


HINTS: dict[str, Callable[[Store, dict, str | None], str]] = {
    "related_indicator_values": _related_indicator_values,
}


# ---------------------------------------------------------------------- checks


@dataclass(frozen=True)
class EvidenceCheck:
    """Query the store for the evidence that would settle this claim."""

    name: str
    rationale: str
    tool: str  # the tool call that must exist for this check to be answerable
    kind: str  # record kind to query
    match: dict[str, str]  # record field -> subject key
    expect: str  # "at_least_one" or "none"
    const: dict[str, Any] = field(default_factory=dict)  # record field -> fixed value
    # What an empty result set means. REFUTED says the evidence is present and
    # contradicts the claim. UNAVAILABLE says the evidence cannot settle it - the
    # difference between "we looked and it is not there" and "this is the wrong
    # place to look", which are not the same refusal and should not read alike.
    absence_is: str = REFUTED
    remedy: str = ""  # what would answer the question, said to the agent
    hint: str = ""  # a HINTS key, consulted when the check fails


@dataclass(frozen=True)
class PredicateCheck:
    """Test a deterministic property of the finding's own subject."""

    name: str
    rationale: str
    subject_key: str
    predicate: str
    expect: bool


Check = EvidenceCheck | PredicateCheck


@dataclass(frozen=True)
class FindingType:
    name: str
    description: str
    subject_keys: tuple[str, ...]
    checks: tuple[Check, ...] = ()


REGISTRY: dict[str, FindingType] = {}


def register(finding_type: FindingType) -> FindingType:
    REGISTRY[finding_type.name] = finding_type
    return finding_type


register(
    FindingType(
        name="process_injection",
        description="A process contains injected or unbacked executable memory.",
        subject_keys=("pid",),
        checks=(
            EvidenceCheck(
                name="malfind_shows_injected_memory",
                rationale=(
                    "Injection is a memory claim. windows.malfind is the tool that would show it."
                    " If malfind ran and returned no region for this PID, the claim is refuted -"
                    " this is how a scary-looking svchost turns out to be an ordinary one."
                ),
                tool="windows.malfind",
                kind="injection_hit",
                match={"pid": "pid"},
                expect="at_least_one",
            ),
        ),
    )
)

register(
    FindingType(
        name="external_c2",
        description="The host communicated with attacker-controlled infrastructure.",
        subject_keys=("foreign_addr",),
        checks=(
            PredicateCheck(
                name="peer_is_routable",
                rationale=(
                    "An internal RFC1918 peer is not external command and control."
                    " Proxy egress to an internal address is the classic false positive here:"
                    " the connection is real, the conclusion is not."
                ),
                subject_key="foreign_addr",
                predicate="is_public_ip",
                expect=True,
            ),
        ),
    )
)

register(
    FindingType(
        name="suspicious_process_chain",
        description="A parent/child process sequence indicative of attacker activity.",
        subject_keys=("pid",),
        checks=(
            EvidenceCheck(
                name="process_exists_in_process_listing",
                rationale="The terminal process of the chain must appear in a process listing.",
                tool="windows.psscan",
                kind="process",
                match={"pid": "pid"},
                expect="at_least_one",
            ),
        ),
    )
)

register(
    FindingType(
        name="process_present",
        description="A named process was running with a given PID.",
        subject_keys=("pid",),
        checks=(
            EvidenceCheck(
                name="process_exists_in_process_listing",
                rationale="A process claim must be backed by a process listing.",
                tool="windows.psscan",
                kind="process",
                match={"pid": "pid"},
                expect="at_least_one",
            ),
        ),
    )
)

register(
    FindingType(
        name="malicious_domain",
        description="A domain name is attacker infrastructure used by this host.",
        subject_keys=("domain",),
        checks=(
            PredicateCheck(
                name="domain_is_not_internal_namespace",
                rationale=(
                    "A name under .lan, .local, .corp and friends cannot resolve on the public"
                    " internet, so it is not external infrastructure. The corporate mail server"
                    " sits in a memory dump looking exactly as suspicious as a C2 does."
                ),
                subject_key="domain",
                predicate="is_internal_namespace",
                expect=False,
            ),
            EvidenceCheck(
                name="domain_appears_in_evidence",
                rationale=(
                    "The name has to be in the image at all. A domain that is close to one in"
                    " evidence but not the one in evidence is the shape a hallucinated indicator"
                    " takes, so near misses are named rather than tolerated."
                ),
                tool="indicators.extract",
                kind="indicator",
                match={"value": "domain"},
                const={"type": "domain"},
                expect="at_least_one",
                absence_is=REFUTED,
                hint="related_indicator_values",
            ),
            EvidenceCheck(
                name="domain_appears_in_execution_context",
                rationale=(
                    "Presence in a raw carve proves the bytes were in RAM, nothing more - every"
                    " domain in every mail the user ever opened is in there too. This check asks"
                    " for the name in something that ran: a command line, a decoded payload, a"
                    " connection. Absent that, the claim is unproven rather than wrong, which is"
                    " the honest verdict on a domain sitting in a strings dump."
                ),
                tool="indicators.extract",
                kind="indicator",
                match={"value": "domain"},
                const={"type": "domain", "execution_context": True},
                expect="at_least_one",
                absence_is=UNAVAILABLE,
                remedy=(
                    "The name is in the image but not in anything that executed."
                    " Attribute it - process command lines, a decoded payload, a connection"
                    " record, or a DNS event - then resubmit."
                ),
            ),
        ),
    )
)

register(
    FindingType(
        name="encoded_payload",
        description="A process carried an encoded payload of a stated content.",
        subject_keys=("blob_sha256",),
        checks=(
            EvidenceCheck(
                name="payload_was_actually_decoded",
                rationale=(
                    "'A base64 gzip blob, probably a stager' is a guess about bytes that either"
                    " decode or do not. The claim is admitted only against a payload this store"
                    " unwrapped, so what it contains is readable rather than asserted."
                ),
                tool="decode.unwrap",
                kind="decoded_payload",
                match={"blob_sha256": "blob_sha256"},
                expect="at_least_one",
                absence_is=REFUTED,
            ),
        ),
    )
)

register(
    FindingType(
        name="observation",
        description=(
            "A bound statement of fact with no conclusion attached. The escape hatch for"
            " something real that no finding type covers yet - still fully bound, but it"
            " carries no analytic claim, so there is nothing to falsify."
        ),
        subject_keys=(),
    )
)


# --------------------------------------------------------------------- results


@dataclass
class CheckResult:
    name: str
    outcome: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.outcome == CORROBORATED


@dataclass
class Falsification:
    passed: bool
    results: list[CheckResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def refuted(self) -> list[CheckResult]:
        return [r for r in self.results if r.outcome == REFUTED]

    @property
    def unavailable(self) -> list[CheckResult]:
        return [r for r in self.results if r.outcome == UNAVAILABLE]


def _run_evidence_check(
    store: Store, check: EvidenceCheck, subject: dict, host: str | None
) -> CheckResult:
    if not store.tool_calls(tool=check.tool, host=host):
        where = f" on {host}" if host else ""
        return CheckResult(
            check.name,
            UNAVAILABLE,
            f"{check.tool} has not been run{where}. Run it, ingest the output, then resubmit.",
        )

    criteria = {field_name: subject[key] for field_name, key in check.match.items()}
    criteria.update(check.const)
    hits = store.query_records(kind=check.kind, host=host, where=criteria)
    described = ", ".join(f"{k}={v}" for k, v in criteria.items())

    def missed(outcome: str, detail: str) -> CheckResult:
        extra = check.remedy and f" {check.remedy}"
        if check.hint:
            extra += HINTS[check.hint](store, subject, host)
        return CheckResult(check.name, outcome, detail + extra)

    if check.expect == "at_least_one":
        if hits:
            return CheckResult(
                check.name, CORROBORATED, f"{check.tool} returned {len(hits)} row(s) for {described}"
            )
        return missed(
            check.absence_is,
            f"{check.tool} ran and returned no {check.kind} row for {described}.",
        )

    if check.expect == "none":
        if hits:
            return CheckResult(
                check.name,
                REFUTED,
                f"{check.tool} returned {len(hits)} row(s) for {described}, expected none",
            )
        return CheckResult(check.name, CORROBORATED, f"{check.tool} returned no row for {described}")

    raise ValueError(f"unknown expect {check.expect!r}")


def _run_predicate_check(check: PredicateCheck, subject: dict) -> CheckResult:
    value = subject[check.subject_key]
    outcome = PREDICATES[check.predicate](value)
    if outcome is None:
        return CheckResult(
            check.name,
            UNAVAILABLE,
            f"{check.predicate} cannot be evaluated for {check.subject_key}={value!r}",
        )
    if outcome == check.expect:
        return CheckResult(check.name, CORROBORATED, f"{check.predicate}({value!r}) is {outcome}")
    return CheckResult(
        check.name,
        REFUTED,
        f"{check.predicate}({value!r}) is {outcome}, the claim requires {check.expect}",
    )


def falsify(
    store: Store, finding_type: str, subject: dict, host: str | None = None
) -> Falsification:
    """Run every registered check for this finding type."""
    if finding_type not in REGISTRY:
        known = ", ".join(sorted(REGISTRY))
        return Falsification(
            passed=False,
            errors=[
                f"no falsification rule registered for finding type {finding_type!r}."
                f" Known types: {known}. Use 'observation' for a bound fact with no"
                " conclusion attached."
            ],
        )

    spec = REGISTRY[finding_type]
    missing = [key for key in spec.subject_keys if key not in subject]
    if missing:
        return Falsification(
            passed=False,
            errors=[f"{finding_type} requires subject key(s): {', '.join(missing)}"],
        )

    results: list[CheckResult] = []
    for check in spec.checks:
        if isinstance(check, EvidenceCheck):
            results.append(_run_evidence_check(store, check, subject, host))
        else:
            results.append(_run_predicate_check(check, subject))

    return Falsification(passed=all(r.ok for r in results), results=results)


def rationale_for(finding_type: str, check_name: str) -> str:
    spec = REGISTRY.get(finding_type)
    if not spec:
        return ""
    for check in spec.checks:
        if check.name == check_name:
            return check.rationale
    return ""
