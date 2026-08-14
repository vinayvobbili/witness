"""The report, and why it is not a summary.

A DFIR report is where a careful investigation usually stops being checkable.
The findings were bound to evidence in a tool; the report is prose about them,
and by the time it reaches a reader the two can only be compared by hand.

So nothing here narrates. The report is rendered *from* the ledger, and every
value it prints is re-read from the store at render time rather than copied from
what the finding claimed when it was admitted. If a record has changed
underneath an admitted finding, the report says so on the line where the value
would have gone, and refuses to be issued.

Two properties follow, and both matter more than the prose:

  * There is no clock in the output. The same case renders the same bytes, so
    the hash of a report is a fact about the case rather than about when someone
    ran the command.
  * The rejections are in the body, not an appendix. A report is worth more when
    you can see what did not make it in - and on this case the refusals are the
    more interesting half.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .falsify import CORROBORATED, REFUTED, UNAVAILABLE, falsify, rationale_for
from .store import Store, coerce, sha256_text
from .verify import _resolve_host

OUTCOME_MARK = {CORROBORATED: "corroborated", REFUTED: "refuted", UNAVAILABLE: "unavailable"}


@dataclass
class BindingView:
    """One cited field, as the finding claimed it and as the store holds it now."""

    record_id: str
    field: str
    claimed: Any
    actual: Any = None
    ok: bool = False
    problem: str = ""


@dataclass
class FindingView:
    finding_id: str
    finding_type: str
    claim: str
    subject: dict
    host: str | None
    status: str
    notes: list[str] = field(default_factory=list)
    bindings: list[BindingView] = field(default_factory=list)
    checks: list[Any] = field(default_factory=list)
    provenance: list[str] = field(default_factory=list)
    retraction_reason: str = ""

    @property
    def holds(self) -> bool:
        return all(b.ok for b in self.bindings) and all(
            c.outcome == CORROBORATED for c in self.checks
        )


@dataclass
class EvidenceView:
    tool: str
    mode: str
    host: str | None
    argv: str
    evidence_path: str | None
    evidence_sha256: str | None
    output_sha256: str
    records: int
    read_from: list[str] = field(default_factory=list)


@dataclass
class Report:
    chain_head: str
    chain_ok: bool
    chain_problems: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    evidence: list[EvidenceView] = field(default_factory=list)
    findings: list[FindingView] = field(default_factory=list)
    rejections: list[dict] = field(default_factory=list)
    retractions: list[dict] = field(default_factory=list)
    counts: dict = field(default_factory=dict)

    @property
    def issuable(self) -> bool:
        """A report is issuable only if everything in it still holds right now."""
        return self.chain_ok and all(f.holds for f in self.findings if f.status == "accepted")

    @property
    def problems(self) -> list[str]:
        out = list(self.chain_problems)
        for finding in self.findings:
            if finding.status != "accepted":
                continue
            for binding in finding.bindings:
                if not binding.ok:
                    out.append(f"{finding.finding_id}: {binding.problem}")
            for check in finding.checks:
                if check.outcome != CORROBORATED:
                    out.append(f"{finding.finding_id}: {check.name} is now {check.outcome}")
        return out

    @property
    def summary(self) -> str:
        return (
            f"{self.counts['findings']} admitted, {self.counts['rejections']} stopped,"
            f" {self.counts['retractions']} retracted,"
            f" {self.counts['tool_calls']} tool call(s) over {len(self.hosts)} host(s)"
        )


def _provenance_line(store: Store, record_id: str) -> str:
    """How far this record sits from the raw capture, written as a path."""
    calls = store.provenance(record_id)
    if not calls:
        return ""
    names = [call["tool"] for call in calls]
    origin = calls[-1]
    tail = origin["evidence_path"] or "<captured output>"
    return " <- ".join(names) + f" <- {tail}"


def build(store: Store, host: str | None = None) -> Report:
    """Render the ledger into a report, re-checking every claim on the way through.

    `host` narrows the report to one machine. Findings are host-scoped already,
    so this only decides what is printed, never what would pass.
    """
    chain_ok, chain_problems = store.verify_chain()

    calls = store.tool_calls()
    if host is not None:
        calls = [call for call in calls if call["host"] == host]

    record_counts: dict[str, int] = {}
    for record in store.query_records():
        record_counts[record["tool_call_id"]] = record_counts.get(record["tool_call_id"], 0) + 1

    evidence: list[EvidenceView] = []
    for call in calls:
        read_from: list[str] = []
        if call.get("derived_from"):
            sources = json.loads(call["derived_from"])
            kinds: dict[str, int] = {}
            for record_id in sources:
                record = store.get_record(record_id)
                if record:
                    kinds[record["kind"]] = kinds.get(record["kind"], 0) + 1
            read_from = [f"{count} {kind} record(s)" for kind, count in sorted(kinds.items())]
        evidence.append(
            EvidenceView(
                tool=call["tool"],
                mode=call["mode"],
                host=call["host"],
                argv=" ".join(json.loads(call["argv"])),
                evidence_path=call["evidence_path"],
                evidence_sha256=call["evidence_sha256"],
                output_sha256=call["output_sha256"],
                records=record_counts.get(call["tool_call_id"], 0),
                read_from=read_from,
            )
        )

    findings: list[FindingView] = []
    for item in store.list_findings():
        record_ids = [b["record_id"] for b in item["bindings"]]
        scope, _ = _resolve_host(store, record_ids, None)
        if host is not None and scope != host:
            continue

        views: list[BindingView] = []
        for binding in item["bindings"]:
            record = store.get_record(binding["record_id"])
            view = BindingView(
                record_id=binding["record_id"],
                field=binding["field"],
                claimed=binding["value"],
            )
            if record is None:
                view.problem = "the cited record is no longer in the store"
            elif binding["field"] not in record["fields"]:
                view.problem = f"the record no longer has a field {binding['field']!r}"
            else:
                view.actual = record["fields"][binding["field"]]
                claimed = coerce(binding["value"])
                actual = coerce(view.actual)
                view.ok = actual == claimed or (
                    isinstance(actual, str)
                    and isinstance(claimed, str)
                    and actual.lower() == claimed.lower()
                )
                if not view.ok:
                    view.problem = (
                        f"record now says {view.actual!r}, the finding claims"
                        f" {binding['value']!r}"
                    )
            views.append(view)

        checks = falsify(store, item["finding_type"], item["subject"], host=scope).results
        provenance = []
        for record_id in dict.fromkeys(record_ids):
            line = _provenance_line(store, record_id)
            if line and line not in provenance:
                provenance.append(line)

        findings.append(
            FindingView(
                finding_id=item["finding_id"],
                finding_type=item["finding_type"],
                claim=item["claim"],
                subject=item["subject"],
                host=scope,
                status=item["status"],
                notes=item["notes"],
                bindings=views,
                checks=checks,
                provenance=provenance,
                retraction_reason=item.get("retraction_reason", ""),
            )
        )

    rejections = store.list_rejections()
    if host is not None:
        rejections = [
            r
            for r in rejections
            if _resolve_host(store, [b["record_id"] for b in r["bindings"]], None)[0]
            in (host, None)
        ]

    retracted_ids = {f.finding_id for f in findings if f.status == "retracted"}
    retractions = [r for r in store.list_retractions() if r["finding_id"] in retracted_ids]

    hosts = sorted({call["host"] for call in calls if call["host"]})
    counts = {
        "tool_calls": len(calls),
        "records": sum(e.records for e in evidence),
        "findings": len([f for f in findings if f.status == "accepted"]),
        "rejections": len(rejections),
        "retractions": len(retractions),
    }

    return Report(
        # The head of the case, not of the chain: a report about a case does not
        # change the case, so a report can be re-rendered byte for byte after it
        # has been issued.
        chain_head=store.case_head(),
        chain_ok=chain_ok,
        chain_problems=chain_problems,
        hosts=hosts,
        evidence=evidence,
        findings=findings,
        rejections=rejections,
        retractions=retractions,
        counts=counts,
    )


def render_markdown(report: Report) -> str:
    """Deterministic markdown. No clock, so the same case is the same bytes."""
    out: list[str] = []
    add = out.append

    add("# Case report")
    add("")
    add(f"Hosts: {', '.join(report.hosts) or 'none'}")
    add(f"Issued from chain head: {report.chain_head}")
    add(f"Chain: {'intact' if report.chain_ok else 'BROKEN'}")
    add(
        f"Counts: {report.counts['tool_calls']} tool call(s),"
        f" {report.counts['records']} record(s),"
        f" {report.counts['findings']} finding(s) admitted,"
        f" {report.counts['rejections']} claim(s) stopped,"
        f" {report.counts['retractions']} retracted"
    )
    add("")
    add(
        "Every value below was re-read from the store while this was written, not"
        " copied from what the finding said when it was admitted."
    )
    if not report.issuable:
        add("")
        add("**This report is not issuable.** Something it depends on no longer holds:")
        for problem in report.problems:
            add(f"- {problem}")

    add("")
    add("## Evidence")
    add("")
    for item in report.evidence:
        where = f" on {item.host}" if item.host else ""
        add(f"- **{item.tool}**{where} ({item.mode})")
        add(f"  - command: `{item.argv}`")
        if item.evidence_path:
            add(f"  - evidence: {item.evidence_path}")
        if item.evidence_sha256:
            add(f"  - evidence sha256: {item.evidence_sha256}")
        add(f"  - output sha256: {item.output_sha256}")
        add(f"  - records: {item.records}")
        for source in item.read_from:
            add(f"  - read: {source}")

    add("")
    add(f"## Findings ({report.counts['findings']} admitted)")
    add("")
    if not report.findings:
        add("No finding survived both gates.")
    for finding in report.findings:
        label = finding.finding_id if finding.status == "accepted" else (
            f"{finding.finding_id} (RETRACTED)"
        )
        add(f"### {label} - {finding.finding_type}")
        add("")
        add(finding.claim)
        add("")
        if finding.subject:
            subject = ", ".join(f"{k}={v}" for k, v in sorted(finding.subject.items()))
            add(f"- Subject: {subject}")
        if finding.host:
            add(f"- Host: {finding.host}")
        add("- Bound to:")
        for binding in finding.bindings:
            if binding.ok:
                add(f"  - {binding.record_id} `{binding.field}` = {binding.actual!r}")
            else:
                add(f"  - {binding.record_id} `{binding.field}` - **{binding.problem}**")
        if finding.checks:
            add("- What would have refuted this, and what the store said:")
            for check in finding.checks:
                add(f"  - {check.name}: **{OUTCOME_MARK[check.outcome]}** - {check.detail}")
                rationale = rationale_for(finding.finding_type, check.name)
                if rationale:
                    add(f"    - why this check exists: {rationale}")
        else:
            add(
                "- No falsification check applies to this finding type: it is a bound"
                " statement of fact with no conclusion attached."
            )
        for line in finding.provenance:
            add(f"- Provenance: {line}")
        for note in finding.notes:
            add(f"- Note: {note}")
        if finding.retraction_reason:
            add(f"- Retracted: {finding.retraction_reason}")
        add("")

    add(f"## Not admitted ({report.counts['rejections']})")
    add("")
    add(
        "Claims that were made and stopped. They are here rather than in an appendix"
        " because a report is worth more when you can see what did not make it in."
    )
    add("")
    for item in report.rejections:
        add(f"- [{item['finding_type']}] {item['claim']}")
        add(f"  - stopped by: {item['reason']}")

    if report.retractions:
        add("")
        add(f"## Retracted ({len(report.retractions)})")
        add("")
        add(
            "Findings that were admitted and later failed a re-check. The original is"
            " never deleted; the retraction sits after it in the chain."
        )
        add("")
        for item in report.retractions:
            add(f"- {item['finding_id']}: {item['reason']}")

    add("")
    add("## Integrity")
    add("")
    add(
        "The store is append-only and hash-chained: tool calls, parsed records, findings,"
        " retractions and rejections are all in the same chain, so evidence cannot be"
        " rewritten under a finding that already cites it."
    )
    add("")
    add(f"- Chain head: {report.chain_head}")
    add(f"- Chain verifies: {report.chain_ok}")
    for problem in report.chain_problems:
        add(f"  - {problem}")
    add(
        "- The head is derived from content alone, so re-deriving this case from the same"
        " captures reproduces this head. `witness replay` does exactly that."
    )
    add("")
    return "\n".join(out)


def render_json(report: Report) -> str:
    """The same report as data, for anything that needs to diff two of them."""
    payload = {
        "chain_head": report.chain_head,
        "chain_ok": report.chain_ok,
        "hosts": report.hosts,
        "counts": report.counts,
        "issuable": report.issuable,
        "evidence": [
            {
                "tool": e.tool,
                "mode": e.mode,
                "host": e.host,
                "argv": e.argv,
                "evidence_path": e.evidence_path,
                "evidence_sha256": e.evidence_sha256,
                "output_sha256": e.output_sha256,
                "records": e.records,
                "read_from": e.read_from,
            }
            for e in report.evidence
        ],
        "findings": [
            {
                "finding_id": f.finding_id,
                "finding_type": f.finding_type,
                "claim": f.claim,
                "subject": f.subject,
                "host": f.host,
                "status": f.status,
                "notes": f.notes,
                "bindings": [
                    {
                        "record_id": b.record_id,
                        "field": b.field,
                        "claimed": b.claimed,
                        "actual": b.actual,
                        "ok": b.ok,
                        "problem": b.problem,
                    }
                    for b in f.bindings
                ],
                "checks": [
                    {"name": c.name, "outcome": c.outcome, "detail": c.detail} for c in f.checks
                ],
                "provenance": f.provenance,
            }
            for f in report.findings
        ],
        "rejections": [
            {
                "finding_type": r["finding_type"],
                "claim": r["claim"],
                "reason": r["reason"],
            }
            for r in report.rejections
        ],
        "retractions": [
            {"finding_id": r["finding_id"], "reason": r["reason"]} for r in report.retractions
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def issue(store: Store, report: Report, text: str) -> dict:
    """Commit a rendered report to the chain it was rendered from.

    Refused if anything the report depends on no longer holds. There is no flag
    that issues it anyway, for the same reason there is none that writes an
    unverified finding.
    """
    if not report.issuable:
        raise ValueError(
            "refusing to issue: " + "; ".join(report.problems[:3])
        )
    return store.add_report(report_sha256=sha256_text(text), summary=report.summary)


def check_issued(store: Store, text: str) -> dict:
    """Was this exact report issued from this store, and does it still hold?

    Two different questions, answered separately. A report can be authentic and
    stale: issued unaltered from this chain, and describing a state the store has
    since moved past.
    """
    digest = sha256_text(text)
    entry = store.find_report(digest)
    current = build(store)
    return {
        "report_sha256": digest,
        "issued": entry is not None,
        "issued_from": entry["chain_head"] if entry else None,
        "current_head": store.case_head(),
        "still_current": bool(entry) and render_markdown(current) == text,
        "still_holds": current.issuable,
        "problems": current.problems,
    }
