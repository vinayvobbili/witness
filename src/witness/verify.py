"""The gate.

A finding is a claim plus bindings. Each binding says: record R, field F, has
value V. This module re-reads R from the store and checks that F really is V.
If any binding fails, the finding is rejected and never reaches the ledger.

This is deliberately not a language model. A second model can be argued out of
a correct refutation; a field comparison cannot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .falsify import CORROBORATED, REFUTED, UNAVAILABLE, CheckResult, falsify
from .store import Store, coerce

# Volatility truncates ImageFileName to the 14 bytes the kernel structure holds.
_TRUNCATION_WIDTH = 14


@dataclass
class Binding:
    record_id: str
    field: str
    value: Any

    def as_dict(self) -> dict:
        return {"record_id": self.record_id, "field": self.field, "value": self.value}


@dataclass
class BindingResult:
    binding: Binding
    ok: bool
    reason: str = ""
    actual: Any = None
    note: str = ""


@dataclass
class Verdict:
    accepted: bool
    results: list[BindingResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def notes(self) -> list[str]:
        return [r.note for r in self.results if r.note]

    @property
    def refutation(self) -> str:
        """One line saying why this died, suitable for the rejection log."""
        for check in self.checks:
            if check.outcome == REFUTED:
                return f"{check.name}: {check.detail}"
        for check in self.checks:
            if check.outcome == UNAVAILABLE:
                return f"{check.name}: {check.detail}"
        for result in self.results:
            if not result.ok:
                return f"{result.binding.record_id}.{result.binding.field}: {result.reason}"
        return "; ".join(self.errors)

    def report(self) -> str:
        lines = ["ACCEPTED" if self.accepted else "REJECTED"]
        for err in self.errors:
            lines.append(f"  error: {err}")
        for res in self.results:
            mark = "ok  " if res.ok else "FAIL"
            lines.append(f"  {mark} {res.binding.record_id} {res.binding.field}={res.binding.value!r}")
            if res.reason:
                lines.append(f"       {res.reason}")
            if res.note:
                lines.append(f"       note: {res.note}")
        for check in self.checks:
            mark = {CORROBORATED: "ok  ", REFUTED: "KILL", UNAVAILABLE: "GAP "}[check.outcome]
            lines.append(f"  {mark} check {check.name}: {check.outcome}")
            lines.append(f"       {check.detail}")
        return "\n".join(lines)


def _check_binding(store: Store, binding: Binding) -> BindingResult:
    record = store.get_record(binding.record_id)
    if record is None:
        return BindingResult(binding, False, reason="no such record in the store")

    if not store.get_tool_call(record["tool_call_id"]):
        return BindingResult(
            binding, False, reason="record has no originating tool call in the audit chain"
        )

    fields = record["fields"]
    if binding.field not in fields:
        available = ", ".join(sorted(fields))
        return BindingResult(
            binding, False, reason=f"record has no field {binding.field!r}; available: {available}"
        )

    actual = fields[binding.field]
    claimed = coerce(binding.value)
    actual_c = coerce(actual)

    # Python says True == 1, so without this a claim of 1 binds to a boolean
    # field like `truncated` and reads in the ledger as though it had been
    # checked against a number.
    if isinstance(actual_c, bool) != isinstance(claimed, bool):
        return BindingResult(
            binding,
            False,
            actual=actual,
            reason=f"record says {actual!r}, claim asserts {binding.value!r} - a boolean"
            " field and a number are not the same value",
        )

    if actual_c == claimed:
        return BindingResult(binding, True, actual=actual)

    # A case-only difference is the same Windows object. Accept it, but say so
    # in the ledger rather than normalising silently.
    if (
        isinstance(actual_c, str)
        and isinstance(claimed, str)
        and actual_c.lower() == claimed.lower()
    ):
        return BindingResult(
            binding,
            True,
            actual=actual,
            note=f"case-normalised: tool emitted {actual!r}, claim said {binding.value!r}",
        )

    reason = f"record says {actual!r}, claim asserts {binding.value!r}"
    if (
        isinstance(actual_c, str)
        and isinstance(claimed, str)
        and len(actual_c) == _TRUNCATION_WIDTH
        and claimed.startswith(actual_c)
    ):
        reason += (
            f" - the tool truncated this field at {_TRUNCATION_WIDTH} characters."
            " Bind to what the tool emitted; the fuller name is not in this evidence."
        )
    return BindingResult(binding, False, reason=reason, actual=actual)


def verify(store: Store, claim: str, bindings: list[Binding]) -> Verdict:
    """Decide whether a claim is supported by the records it cites."""
    errors: list[str] = []

    if not claim.strip():
        errors.append("empty claim")
    if not bindings:
        errors.append("unsupported claim: a finding must cite at least one record field")

    results = [_check_binding(store, b) for b in bindings]

    chain_ok, chain_problems = store.verify_chain()
    if not chain_ok:
        errors.append("audit chain is broken: " + "; ".join(chain_problems[:3]))

    accepted = not errors and all(r.ok for r in results)
    return Verdict(accepted=accepted, results=results, errors=errors)


def _ground_subject(subject: dict, results: list[BindingResult]) -> list[str]:
    """Every subject value must be one the bindings actually proved.

    Without this an agent could bind records for PID 3720 and then declare the
    subject to be PID 4 - the checks would run against the wrong process and
    corroborate a claim nobody made.
    """
    proved = [coerce(r.actual) for r in results if r.ok]
    return [
        f"subject {key}={value!r} is not proved by any binding on this finding"
        for key, value in subject.items()
        if coerce(value) not in proved
    ]


def _resolve_host(
    store: Store, record_ids: list[str], declared: str | None
) -> tuple[str | None, list[str]]:
    """Work out which host a finding is about, and refuse if the answer is muddy.

    Falsification checks are host-scoped, so the host has to come from the
    evidence rather than from the prose of the claim - a sentence naming a host
    is not checkable, and a finding whose bindings span two machines has no
    single host for the checks to run against.
    """
    hosts = {store.host_for_record(rid) for rid in record_ids if store.get_record(rid)}
    hosts.discard(None)
    if len(hosts) > 1:
        listed = ", ".join(sorted(hosts))
        return None, [
            f"bindings cite evidence from more than one host ({listed});"
            " a finding is about one host, so split it"
        ]
    resolved = next(iter(hosts), None)
    if declared is not None and resolved is not None and declared != resolved:
        return None, [
            f"finding declares host {declared!r} but its evidence comes from {resolved!r}"
        ]
    return declared if resolved is None else resolved, []


def submit_finding(
    store: Store,
    *,
    finding_type: str,
    claim: str,
    bindings: list[Binding],
    subject: dict | None = None,
    host: str | None = None,
) -> tuple[Verdict, str | None]:
    """Both gates, then the ledger.

    Gate one: every cited field really says what the claim says it says.
    Gate two: the evidence that would refute this claim was looked for and is
    not there.

    Returns the verdict and the finding id, which is None when rejected. There
    is no flag that writes a finding that failed either gate - that is the point.
    """
    subject = subject or {}
    verdict = verify(store, claim, bindings)

    if verdict.accepted:
        grounding_errors = _ground_subject(subject, verdict.results)
        scope, host_errors = _resolve_host(store, [b.record_id for b in bindings], host)
        falsification = falsify(store, finding_type, subject, host=scope)
        verdict.checks = falsification.results
        verdict.errors.extend(grounding_errors)
        verdict.errors.extend(host_errors)
        verdict.errors.extend(falsification.errors)
        verdict.accepted = (
            not grounding_errors
            and not host_errors
            and not falsification.errors
            and falsification.passed
        )

    if not verdict.accepted:
        store.add_rejection(
            finding_type=finding_type,
            claim=claim,
            reason=verdict.refutation,
            bindings=[b.as_dict() for b in bindings],
            subject=subject,
            host=host,
        )
        return verdict, None

    finding_id = store.add_finding(
        finding_type=finding_type,
        claim=claim,
        bindings=[b.as_dict() for b in bindings],
        notes=verdict.notes,
        subject=subject,
    )
    return verdict, finding_id


def revalidate(store: Store) -> list[tuple[str, str]]:
    """Re-run every check over the accepted ledger and retract what now fails.

    This is what makes the matrix retroactive: a finding admitted before the
    refuting tool was ingested does not stay admitted once that tool's output
    lands. Returns the (finding_id, reason) pairs retracted by this pass.
    """
    retracted: list[tuple[str, str]] = []
    for item in store.list_findings():
        if item["status"] == "retracted":
            continue
        bindings = item["bindings"]
        host, _ = _resolve_host(store, [b["record_id"] for b in bindings], None)

        rebound = verify(store, item["claim"], [Binding(**b) for b in bindings])
        if not rebound.accepted:
            reason = f"bindings no longer verify: {rebound.refutation}"
            store.add_retraction(finding_id=item["finding_id"], reason=reason)
            retracted.append((item["finding_id"], reason))
            continue

        falsification = falsify(store, item["finding_type"], item["subject"], host=host)
        if falsification.refuted:
            check = falsification.refuted[0]
            reason = f"refuted on revalidation by {check.name}: {check.detail}"
            store.add_retraction(finding_id=item["finding_id"], reason=reason)
            retracted.append((item["finding_id"], reason))
    return retracted
