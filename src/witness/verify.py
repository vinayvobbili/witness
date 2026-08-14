"""The gate.

A finding is a claim plus bindings. Each binding says: record R, field F, has
value V. This module re-reads R from the store and checks that F really is V.
If any binding fails, the finding is rejected and never reaches the ledger.

This is deliberately not a language model. A second model can be argued out of
a correct refutation; a field comparison cannot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .store import Store

_INT_RE = re.compile(r"^-?\d+$")
_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")

# Volatility truncates ImageFileName to the 14 bytes the kernel structure holds.
_TRUNCATION_WIDTH = 14


def coerce(value: Any) -> Any:
    """Make a claimed value comparable to a parsed one without softening it.

    Numbers written as strings become numbers; hex offsets become integers.
    Nothing else is changed - in particular no substring or fuzzy matching.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value).strip()
    if _INT_RE.match(text):
        return int(text)
    if _HEX_RE.match(text):
        return int(text, 16)
    return text


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

    @property
    def notes(self) -> list[str]:
        return [r.note for r in self.results if r.note]

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


def submit_finding(
    store: Store, *, finding_type: str, claim: str, bindings: list[Binding]
) -> tuple[Verdict, str | None]:
    """Verify, then write to the ledger only on success.

    Returns the verdict and the finding id, which is None when rejected. There
    is no flag that writes an unverified finding anyway - that is the point.
    """
    verdict = verify(store, claim, bindings)
    if not verdict.accepted:
        return verdict, None
    finding_id = store.add_finding(
        finding_type=finding_type,
        claim=claim,
        bindings=[b.as_dict() for b in bindings],
        notes=verdict.notes,
    )
    return verdict, finding_id
