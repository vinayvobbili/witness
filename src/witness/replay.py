"""Re-derive a whole case from the captures, and see whether you get it back.

Every id in this store is derived from content: a tool call id from the tool,
its arguments and the hash of its output; a record id from the call that emitted
it; a finding id from its type, claim, bindings and subject. Nothing is derived
from a clock or a counter. So the chain head is a fingerprint of the case, and
two people who run the same pipeline over the same captures on two machines
either agree on that hash or do not have the same case.

`replay` is what turns that from an argument into a command. It walks the chain
of an existing store entry by entry and performs each step again into a fresh
one: re-parsing each capture, re-running each derived analyser, and re-submitting
every finding *and every rejection* through both gates. Then it compares heads.

Re-submitting the rejections is the half that is easy to skip and worth keeping.
A case that can only replay what it accepted has shown that its conclusions are
reproducible while leaving its refusals as assertions.

Captures are matched to tool calls by hash, never by filename. An edited fixture
does not quietly replay as itself under the name it used to have; it fails to
match anything and is reported as missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import report as report_module
from .collectors import decode, indicators, rawstrings, structured
from .collectors.volatility import PLUGINS
from .collectors.volatility import ingest_capture as ingest_volatility
from .store import Store, sha256_text
from .verify import Binding, revalidate, submit_finding

# tool name as recorded in the chain -> how to run it again
_VOLATILITY_TOOLS = {f"windows.{name}": name for name in PLUGINS}


@dataclass
class Step:
    kind: str
    label: str
    ok: bool
    detail: str = ""


@dataclass
class ReplayResult:
    source_head: str
    replayed_head: str
    steps: list[Step] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    source_findings: list[str] = field(default_factory=list)
    replayed_findings: list[str] = field(default_factory=list)
    source_rejections: list[str] = field(default_factory=list)
    replayed_rejections: list[str] = field(default_factory=list)

    @property
    def findings_match(self) -> bool:
        return self.source_findings == self.replayed_findings

    @property
    def rejections_match(self) -> bool:
        return self.source_rejections == self.replayed_rejections

    @property
    def head_matches(self) -> bool:
        return self.source_head == self.replayed_head

    @property
    def ok(self) -> bool:
        return (
            not self.missing
            and not self.problems
            and self.findings_match
            and self.rejections_match
            and self.head_matches
        )

    def report(self) -> str:
        lines = []
        for step in self.steps:
            mark = "ok  " if step.ok else "FAIL"
            lines.append(f"  {mark} {step.kind:<10} {step.label}")
            if step.detail:
                lines.append(f"       {step.detail}")
        lines.append("")
        lines.append(f"  findings   {len(self.replayed_findings)} of {len(self.source_findings)}"
                     f" reproduced with identical ids: {self.findings_match}")
        lines.append(f"  rejections {len(self.replayed_rejections)} of"
                     f" {len(self.source_rejections)} reproduced: {self.rejections_match}")
        lines.append(f"  source head   {self.source_head}")
        lines.append(f"  replayed head {self.replayed_head}")
        lines.append(f"  identical: {self.head_matches}")
        for item in self.missing:
            lines.append(f"  missing capture: {item}")
        for item in self.problems:
            lines.append(f"  problem: {item}")
        return "\n".join(lines)


def index_captures(paths: list[str | Path]) -> dict[str, Path]:
    """Hash every candidate capture the way the collector that read it would.

    Keyed by content, so which directory a capture is sitting in and what it is
    called are both irrelevant - which is the point. A renamed capture still
    replays; an edited one does not.
    """
    index: dict[str, Path] = {}
    for root in paths:
        root = Path(root)
        candidates = sorted(root.rglob("*")) if root.is_dir() else [root]
        for path in candidates:
            if not path.is_file() or path.suffix in {".db", ".pyc"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            index.setdefault(sha256_text(text), path)
    return index


def _replay_tool_call(into: Store, payload: dict, captures: dict[str, Path]) -> Step:
    tool = payload["tool"]
    host = payload.get("host")

    if payload["mode"] == "derived":
        try:
            if tool == decode.TOOL:
                result = decode.unwrap(into, host=host)
            elif tool == indicators.TOOL:
                result = indicators.extract(into, host=host)
            else:
                return Step("derive", tool, False, f"no replay handler for derived tool {tool!r}")
        except ValueError as exc:
            # An analyser with nothing to read is the downstream symptom of a
            # capture that did not arrive. Report it as a failed step rather than
            # ending the replay - the run should name every gap, not the first.
            return Step("derive", f"{tool} on {host}", False, str(exc))
        same = result["tool_call_id"] == payload["tool_call_id"]
        return Step(
            "derive",
            f"{tool} on {host}",
            same,
            "" if same else f"produced tool call {result['tool_call_id']},"
                            f" expected {payload['tool_call_id']}",
        )

    path = captures.get(payload["output_sha256"])
    if path is None:
        return Step(
            "ingest",
            f"{tool} on {host}",
            False,
            f"no capture matching sha256 {payload['output_sha256'][:16]}... was supplied",
        )

    common = dict(
        output_path=path,
        host=host,
        evidence_path=payload.get("evidence_path"),
        evidence_sha256=payload.get("evidence_sha256"),
    )
    if tool == rawstrings.TOOL:
        result = rawstrings.ingest_capture(into, **common)
    elif tool in _VOLATILITY_TOOLS:
        result = ingest_volatility(into, plugin_name=_VOLATILITY_TOOLS[tool], **common)
    elif tool.startswith(structured.TOOL_PREFIX):
        # Routed by prefix rather than by a registry: a structured response can
        # come from any service, and a replay that only recognised the ones this
        # build had heard of would fail on a case built by a later one.
        try:
            options = structured.from_argv(payload["argv"])
        except structured.ParseError as exc:
            return Step("ingest", tool, False, str(exc))
        result = structured.ingest_capture(into, **common, **options)
    else:
        return Step("ingest", tool, False, f"no replay handler for tool {tool!r}")

    same = result["tool_call_id"] == payload["tool_call_id"]
    return Step(
        "ingest",
        f"{tool} on {host}",
        same,
        f"{path.name}, {result['records']} record(s)"
        if same
        else f"{path.name} produced tool call {result['tool_call_id']},"
             f" expected {payload['tool_call_id']}",
    )


def _replay_claim(into: Store, payload: dict) -> tuple[Step, str | None, str | None]:
    """Put a claim back through both gates and see where it lands this time."""
    bindings = [Binding(**b) for b in payload.get("bindings", [])]
    try:
        verdict, finding_id = submit_finding(
            into,
            finding_type=payload["finding_type"],
            claim=payload["claim"],
            bindings=bindings,
            subject=payload.get("subject", {}),
            host=payload.get("host"),
        )
    except Exception as exc:  # noqa: BLE001 - a replay reports failures, it does not raise them
        kind = "finding" if payload.get("finding_id") else "rejection"
        return Step(kind, payload["claim"][:64], False, f"{type(exc).__name__}: {exc}"), None, None
    expected_finding = payload.get("finding_id")
    if expected_finding:
        ok = finding_id == expected_finding
        detail = "" if ok else (
            f"was admitted as {expected_finding}, now {finding_id or 'rejected'}"
            f" - {verdict.refutation}"
        )
        return Step("finding", payload["claim"][:64], ok, detail), finding_id, None

    ok = finding_id is None
    detail = "" if ok else f"was rejected, now admitted as {finding_id}"
    return Step("rejection", payload["claim"][:64], ok, detail), None, payload["rejection_id"]


def replay(source: Store, inputs: list[str | Path], into: Store) -> ReplayResult:
    """Rebuild `source` into `into` from the captures under `inputs`."""
    captures = index_captures(inputs)
    result = ReplayResult(source_head="", replayed_head="")
    revalidated = False

    for entry in source.chain_entries():
        kind, payload = entry["kind"], entry["payload"]

        if kind == "record":
            continue  # written as a side effect of the call that emitted it

        if kind == "tool_call":
            step = _replay_tool_call(into, payload, captures)
            result.steps.append(step)
            if not step.ok:
                (result.missing if "no capture matching" in step.detail else result.problems).append(
                    f"{payload['tool']}: {step.detail}"
                )

        elif kind in ("finding", "rejection"):
            step, finding_id, rejection_id = _replay_claim(into, payload)
            result.steps.append(step)
            if kind == "finding":
                result.source_findings.append(payload["finding_id"])
                if finding_id:
                    result.replayed_findings.append(finding_id)
            else:
                result.source_rejections.append(payload["rejection_id"])
                if rejection_id:
                    result.replayed_rejections.append(rejection_id)
            if not step.ok:
                result.problems.append(f"{payload['claim'][:60]}: {step.detail}")

        elif kind == "retraction":
            # Retractions are not replayed one at a time - they are what a
            # revalidation pass decides. Run the pass once and let the head
            # comparison say whether it decided the same thing.
            if not revalidated:
                revalidate(into)
                revalidated = True
                result.steps.append(Step("revalidate", "re-run every check over the ledger", True))

        elif kind == "report":
            built = report_module.build(into)
            text = report_module.render_markdown(built)
            digest = sha256_text(text)
            same = digest == payload["report_sha256"]
            result.steps.append(
                Step(
                    "report",
                    "re-render the issued report",
                    same,
                    "" if same else f"rendered {digest[:16]}...,"
                                    f" issued was {payload['report_sha256'][:16]}...",
                )
            )
            if same:
                report_module.issue(into, built, text)
            else:
                result.problems.append("the report does not re-render to the bytes that were issued")

    result.source_head = source.head()
    result.replayed_head = into.head()
    return result
