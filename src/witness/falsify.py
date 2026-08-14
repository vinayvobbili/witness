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


PREDICATES: dict[str, Callable[[Any], bool | None]] = {
    "is_public_ip": _is_public_ip,
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
    hits = store.query_records(kind=check.kind, host=host, where=criteria)
    described = ", ".join(f"{k}={v}" for k, v in criteria.items())

    if check.expect == "at_least_one":
        if hits:
            return CheckResult(
                check.name, CORROBORATED, f"{check.tool} returned {len(hits)} row(s) for {described}"
            )
        return CheckResult(
            check.name,
            REFUTED,
            f"{check.tool} ran and returned no {check.kind} row for {described}",
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
