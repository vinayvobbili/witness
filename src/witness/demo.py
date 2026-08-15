"""The guided tour: one command, no key, no image, no dependencies.

Somebody who has ten minutes should not have to assemble the argument out of
three scripts and a README. This runs the whole case front to back and narrates
it, and it is the thing to run first.

It is a demo with a spine. Every beat below declares what it expects the gate to
do *before* the gate is asked, and a beat that lands the other way makes the run
exit non-zero. A demo that narrates whatever happened is a demo that goes on
looking impressive after the tool underneath it has broken - which is the same
failure this project exists to refuse, wearing a different hat.

Nothing here is quoted from a script either. Every count printed at the end is
read back out of the store the run just built.
"""

from __future__ import annotations

import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import casefile, report as report_module
from .replay import replay
from .store import Store
from .style import OFF, Style
from .verify import Binding, submit_finding

ADMIT = "admitted"
REFUSE = "refused"

# Wrapped to something a terminal shows without folding, because a demo that
# wraps mid-word in a screen recording is a demo nobody watches twice.
WIDTH = 78


def wrap(
    label: str,
    body: str,
    indent: int = 6,
    paint: Callable[[str], str] | None = None,
) -> list[str]:
    """`label  body`, folded under the body's own left margin.

    `paint` is applied to the label field after folding rather than before,
    because escape codes are bytes and `textwrap` would count them as width.
    The field is eight columns whether it is painted or not.
    """

    lead = " " * indent + label.ljust(8) + " "
    lines = textwrap.wrap(
        body,
        width=WIDTH,
        initial_indent=lead,
        subsequent_indent=" " * len(lead),
    ) or [lead.rstrip()]
    if paint is not None and label:
        first = lines[0]
        field = first[indent : indent + 8]
        lines[0] = first[:indent] + paint(field) + first[indent + 8 :]
    return lines


@dataclass(frozen=True)
class Beat:
    """One claim, and what the gate is expected to do with it.

    `why` is the point of the beat - the thing a viewer is supposed to take
    away - and `expect` is what makes the demo checkable rather than merely
    narrated.
    """

    title: str
    why: str
    expect: str
    finding_type: str
    claim: str
    bindings: list[Binding]
    subject: dict


@dataclass
class Result:
    beat: Beat
    admitted: bool
    detail: str
    finding_id: str | None = None

    @property
    def as_scripted(self) -> bool:
        return self.admitted == (self.beat.expect == ADMIT)


@dataclass
class Tour:
    """What the run did, so a caller can check it instead of reading the prose."""

    records: int = 0
    results: list[Result] = field(default_factory=list)
    findings: int = 0
    rejections: int = 0
    chain_entries: int = 0
    chain_ok: bool = False
    report_sha256: str = ""
    replay_ok: bool = False
    replayed_head: str = ""
    head: str = ""

    @property
    def off_script(self) -> list[Result]:
        return [r for r in self.results if not r.as_scripted]

    @property
    def ok(self) -> bool:
        return (
            not self.off_script
            and self.chain_ok
            and self.replay_ok
            and bool(self.report_sha256)
        )


def script(store: Store) -> list[Beat]:
    """The beats, built against the store so no id in them is hand-copied.

    Six claims, chosen because each one dies - or lives - for a different
    reason. Two of them are true. The other four are the four ways a confident
    forensics writeup is usually wrong.
    """

    def process(host: str, pid: int) -> str:
        return store.query_records(kind="process", host=host, where={"pid": pid})[0]["record_id"]

    def endpoint(host: str, **criteria: Any) -> str:
        hits = store.query_records(kind="network_endpoint", host=host, where=criteria)
        return hits[0]["record_id"]

    def indicator(value: str, host: str = "base-wkstn-05") -> str:
        hits = store.query_records(kind="indicator", host=host, where={"value": value})
        return hits[0]["record_id"]

    embedded_c2 = "aaa.stage.9231829.extranet.wagonwheelgifts.com"

    return [
        Beat(
            title="the kill chain, every link bound to a field",
            why="this one is true, and it has to survive - a gate that refuses"
            " everything is not a gate, it is an off switch",
            expect=ADMIT,
            finding_type="suspicious_process_chain",
            claim="WmiPrvSE.exe (2676) spawned powershell.exe (3920), which spawned"
            " powershell.exe (1332), which spawned rundll32.exe (3720).",
            bindings=[
                Binding(process("base-wkstn-05", 2676), "image_file_name", "WmiPrvSE.exe"),
                Binding(process("base-wkstn-05", 3920), "ppid", 2676),
                Binding(process("base-wkstn-05", 1332), "ppid", 3920),
                Binding(process("base-wkstn-05", 3720), "ppid", 1332),
                Binding(process("base-wkstn-05", 3720), "pid", 3720),
                Binding(process("base-wkstn-05", 3720), "image_file_name", "rundll32.exe"),
            ],
            subject={"pid": 3720},
        ),
        Beat(
            title="an address that is in no record anywhere",
            why="the invented indicator - the failure mode that put this repo here",
            expect=REFUSE,
            finding_type="external_c2",
            claim="The host beaconed to external C2 185.220.101.5.",
            bindings=[Binding("nonexistent#0001", "foreign_addr", "185.220.101.5")],
            subject={"foreign_addr": "185.220.101.5"},
        ),
        Beat(
            title="one digit wrong, against a record that really exists",
            why="the citation is genuine and the value is not; a gate that checks"
            " provenance alone passes this",
            expect=REFUSE,
            finding_type="suspicious_process_chain",
            claim="rundll32.exe (3720) was spawned by powershell.exe (1233).",
            bindings=[Binding(process("base-wkstn-05", 3720), "ppid", 1233)],
            subject={"pid": 3720},
        ),
        Beat(
            title="every binding verifies and the conclusion is still wrong",
            why="quoting the evidence perfectly and reading it wrongly is the harder"
            " failure, and gate 1 does nothing about it",
            expect=REFUSE,
            finding_type="external_c2",
            claim="svchost.exe beaconed to external C2 at 172.16.4.10:8080.",
            bindings=[
                Binding(
                    endpoint("base-wkstn-01", foreign_addr="172.16.4.10", foreign_port=8080),
                    "foreign_addr",
                    "172.16.4.10",
                ),
                Binding(
                    endpoint("base-wkstn-01", foreign_addr="172.16.4.10", foreign_port=8080),
                    "foreign_port",
                    8080,
                ),
            ],
            subject={"foreign_addr": "172.16.4.10"},
        ),
        Beat(
            title="nobody ran the tool that would settle it",
            why="unavailable is not a pass; the claim is held and the missing tool"
            " is named",
            expect=REFUSE,
            finding_type="process_injection",
            claim="rundll32.exe (3720) on base-wkstn-05 contains injected code.",
            bindings=[Binding(process("base-wkstn-05", 3720), "pid", 3720)],
            subject={"pid": 3720},
        ),
        Beat(
            title="a domain in the image, tied to nothing that ran",
            why="this is the intrusion's real C2 and it is still refused - being"
            " right about the case is not the same as being shown by the evidence",
            expect=REFUSE,
            finding_type="malicious_domain",
            claim="The host beaconed to external C2 www.venetodns.trade.",
            bindings=[Binding(indicator("www.venetodns.trade"), "value", "www.venetodns.trade")],
            subject={"domain": "www.venetodns.trade"},
        ),
        Beat(
            title="the C2 that only exists once you decode for it",
            why="two layers down inside a carved command line, in something that ran"
            " - and absent from the graded run this replaces",
            expect=ADMIT,
            finding_type="malicious_domain",
            claim="The in-memory PowerShell stager carries shellcode that beacons to"
            f" {embedded_c2}.",
            bindings=[Binding(indicator(embedded_c2), "value", embedded_c2)],
            subject={"domain": embedded_c2},
        ),
    ]


def catalogue_sizes(root: Path) -> dict[str, int] | None:
    """Counts for the two suites this tour does not run.

    Reported as the size of a catalogue, never as a result. Saying "119 attacks
    held" in a run that executed none of them would be this project's own
    failure mode in its own marketing copy.

    Returns None when the suites are not on disk - the tour ships inside the
    package and can be run from an install that has no tests directory.
    """
    import sys

    tests = root / "tests"
    if not (tests / "adversarial.py").exists() or not (tests / "corpus.py").exists():
        return None
    if str(tests) not in sys.path:
        sys.path.insert(0, str(tests))
    try:
        import adversarial  # noqa: PLC0415
        import corpus  # noqa: PLC0415
    except ImportError:  # pragma: no cover - a partial checkout, not a supported state
        return None
    families = adversarial.families()
    return {
        "families": len(families),
        "attacks": sum(len(f.attacks) for f in families),
        "classes": len(corpus.CLASSES),
    }


def run(
    fixtures: Path,
    *,
    store_path: Path,
    root: Path | None = None,
    pace: float = 0.0,
    out: Callable[[str], None] = print,
    style: Style | None = None,
) -> Tour:
    """The tour. Returns what it found, having narrated it on the way.

    `style` defaults to off, so a caller that captures `out` gets the same
    bytes it always did and only the two entry points a human types decide to
    paint anything.
    """

    paint = style or OFF

    def rule(title: str, subtitle: str = "") -> None:
        out("")
        out(paint.quiet("=" * 76))
        out(f"  {paint.heading(title)}")
        if subtitle:
            out(f"  {paint.quiet(subtitle)}")
        out(paint.quiet("=" * 76))
        if pace:
            time.sleep(pace)

    tour = Tour()
    store = Store(store_path)

    rule(
        "THE EVIDENCE",
        "captured Volatility 3 output from the SANS SRL-2018 case. No image, no key.",
    )
    loaded = casefile.load(
        store,
        fixtures,
        on_capture=lambda capture, result: out(
            f"  {capture.host}  {paint.quiet(capture.tool.ljust(16))}"
            f" {result['records']:>4} records"
            f"   sha256(output) {result['output_sha256'][:12]}..."
        ),
    )
    for host, derived in loaded["derived"].items():
        unwrapped, extracted = derived["decode"], derived["indicators"]
        decode_col = paint.quiet("decode.unwrap".ljust(16))
        indicator_col = paint.quiet("indicators".ljust(16))
        out(
            f"  {host}  {decode_col} {unwrapped['payloads']:>4} payloads"
            f"   unwrapped from {unwrapped['blobs']} blob(s), {unwrapped['stages']} stage(s) deep"
        )
        out(
            f"  {host}  {indicator_col} {extracted['indicators']:>4} indicators"
            f"   {extracted['in_execution_context']} of them in something that executed"
        )
    tour.records = len(store.query_records())
    out("")
    out(
        f"  {tour.records} records across {len(casefile.HOSTS)} hosts - one clean baseline and"
        " one compromised"
    )
    out("  workstation. Every record carries the hash of the tool output it was parsed from.")

    rule(
        "THE GATE",
        "seven claims. Each one says up front what it expects, so this can fail.",
    )
    for number, beat in enumerate(script(store), start=1):
        out("")
        out(f"  {paint.heading(f'[{number}] {beat.title}')}")
        for line in wrap("why", beat.why, paint=paint.quiet):
            out(line)
        for line in wrap("claim", beat.claim, paint=paint.quiet):
            out(line)
        verdict, finding_id = submit_finding(
            store,
            finding_type=beat.finding_type,
            claim=beat.claim,
            bindings=beat.bindings,
            subject=beat.subject,
        )
        detail = (
            f"{len(beat.bindings)} binding(s) re-read and matched"
            if verdict.accepted
            else verdict.refutation
        )
        result = Result(beat, verdict.accepted, detail, finding_id)
        tour.results.append(result)
        for line in wrap(
            "ADMITTED" if verdict.accepted else "REFUSED",
            detail,
            paint=lambda field: paint.verdict_badge(verdict.accepted, field),
        ):
            out(line)
        if finding_id:
            out(" " * 15 + paint.quiet(f"ledger {finding_id}"))
        if not result.as_scripted:
            out(f"      {paint.warning('OFF SCRIPT')}  this beat expected {beat.expect}")
        if pace:
            time.sleep(pace)

    rule("THE REPORT", "rendered from the ledger, re-reading every value as it writes")
    built = report_module.build(store)
    text = report_module.render_markdown(built)
    entry = report_module.issue(store, built, text)
    tour.report_sha256 = entry["report_sha256"]
    out(f"  {built.summary}")
    out(f"  {len(text.splitlines())} lines, and not one timestamp in them.")
    out(f"  sha256 {tour.report_sha256}")
    out("")
    out("  The rejections are in the body, not an appendix. A report is worth more when")
    out("  you can see what did not make it in.")

    rule("REPLAY", "throw the case away and rebuild it from the captures alone")
    rebuilt = Store(store_path.parent / "replayed.db")
    outcome = replay(store, [fixtures], rebuilt)
    tour.replay_ok = outcome.ok
    tour.replayed_head = outcome.replayed_head
    out("  Nothing here is numbered from a clock or a counter, so the chain head is a")
    out("  fingerprint of the case rather than of the run.")
    out("")
    out(f"  {paint.quiet('original head')}  {outcome.source_head}")
    out(f"  {paint.quiet('replayed head')}  {outcome.replayed_head}")
    out(
        f"  {paint.quiet('match')}          "
        f"{paint.verdict(outcome.head_matches, str(outcome.head_matches))}"
        f"   ({len(outcome.replayed_findings)} findings and"
        f" {len(outcome.replayed_rejections)} refusals came back, in order)"
    )
    if not outcome.ok:
        for problem in (outcome.problems + outcome.missing)[:5]:
            out(f"  problem        {problem}")

    tour.findings = len(store.list_findings())
    tour.rejections = len(store.list_rejections())
    tour.chain_entries = len(store.chain_entries())
    tour.chain_ok, chain_problems = store.verify_chain()
    tour.head = store.head()

    rule("WHAT THIS RUN LEFT BEHIND", "every number below was read back out of the store")
    out(f"  {tour.records} records   {tour.findings} findings   {tour.rejections} refusals"
        f"   {tour.chain_entries} entries in the audit chain")
    out(
        f"  {paint.quiet('chain intact:')} "
        f"{paint.verdict(tour.chain_ok, str(tour.chain_ok))}"
        + ("" if tour.chain_ok else f"  {chain_problems[:2]}")
    )
    out(f"  {paint.quiet('head')}          {tour.head}")
    if tour.off_script:
        out("")
        for result in tour.off_script:
            out(
                f"  {paint.warning('OFF SCRIPT')}  {result.beat.title}"
                f"  expected {result.beat.expect}, got"
                f" {'admitted' if result.admitted else 'refused'}"
            )

    sizes = catalogue_sizes(root) if root else None
    rule("WHERE TO GO NEXT", "this tour proves nothing about the two hardest questions")
    out("  What a hostile string in the image can make this say, and how much true work")
    out("  it throws away being careful, are both measured - and neither by this run.")
    out("")
    if sizes:
        out(
            f"  {paint.heading('python scripts/adversarial.py')}"
            f"   {sizes['attacks']} crafted attacks,"
            f" {sizes['families']} families, one invariant each"
        )
        out(
            f"  {paint.heading('python scripts/accuracy.py')}"
            f"      1,000+ claims in {sizes['classes']} classes"
            " of ordinary analytical error"
        )
        out(
            f"  {paint.heading('python scripts/prove.py')}"
            "         the long-form version of the run above"
        )
        out(f"  {paint.heading('pytest')}                          the lot, as assertions")
        out("")
        out("  The two numbers above are catalogue sizes, not results. This run executed")
        out("  neither suite; those commands do, and both print the argument, not a score.")
    else:
        out("  python scripts/adversarial.py   the attack catalogue, family by family")
        out("  python scripts/accuracy.py      precision, recall, and the reason each refusal gave")
        out("  python scripts/prove.py         the long-form version of the run above")
        out("  pytest                          the lot, as assertions")
    return tour
