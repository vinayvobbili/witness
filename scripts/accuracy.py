#!/usr/bin/env python3
"""How often is it right, and what does being right cost?

The adversarial suite measures resistance to a crafted attack. This measures
something less dramatic and more useful: ordinary accuracy. Every record in the
shipped case is put through the gate as a claim that is true, and as claims that
are false in each of the ways analysis actually goes wrong.

Two numbers matter and only one of them ever gets published. Precision - of what
was admitted, how much was true - is the number a tool that refuses everything
scores perfectly on. Recall - of what was true, how much was admitted - is the
bill for it. Both are below, and so is the list of every case that came out
wrong, because an accuracy report with no cost column is an advertisement.
"""

from __future__ import annotations

import sys
import tempfile
import textwrap
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from witness import casefile, report  # noqa: E402
from witness.store import Store  # noqa: E402

import corpus  # noqa: E402


# The scored corpus asks whether the evidence in this repository supports a
# claim. The SANS scenario is a separate source of truth, and where the two
# disagree the disagreement belongs in the report rather than in a footnote.
KNOWN_MISSES = (
    "www.venetodns.trade is the intrusion's real C2, corroborated on the disk image by"
    " PSRemoting and Empire artefacts. This tool refuses it. In the exported captures the"
    " name appears in a raw carve and in nothing that executed, so the refusal is right on"
    " this evidence and is still a miss on this case. Ingest the PowerShell command that"
    " carries it and the same claim is admitted.",
    "The intrusion's entry vector - PSRemoting as a stolen SQL service account, reaching"
    " wsmprovhost - is on the disk image, in Sysmon and PowerShell event logs. None of that"
    " was exported, so there is no claim about it to admit or refuse. Not a miss by the"
    " gate; a gap in what this repository can be pointed at.",
    "The other direction: decoding the carved stager recovers"
    " aaa.stage.9231829.extranet.wagonwheelgifts.com, a DNS-beacon hostname embedded in the"
    " second-stage shellcode, in something that ran. It is admitted here and does not appear"
    " in the graded run this project was built to improve on.",
    "base-wkstn-01 has nothing to miss - it is a clean baseline. The accuracy result on it is"
    " the one that matters for a clean host: every attempt in this corpus to make it look"
    " compromised was refused, and the count is on the ledger line below.",
)


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def pct(part: int, whole: int) -> str:
    return "n/a" if not whole else f"{100.0 * part / whole:.1f}%"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "accuracy.db")

        rule("CASE  the evidence this is measured on")
        print(
            "  SANS SRL-2018 'Compromised Enterprise Network'. Two hosts: a clean\n"
            "  Windows 10 baseline and the Win7 workstation with the intrusion on it.\n"
            "  This is the whole of the exported evidence, not a sample of it."
        )
        print()
        loaded = casefile.load(
            store,
            ROOT / "fixtures",
            on_capture=lambda capture, result: print(
                f"  {capture.host}  {capture.tool:<16} {result['records']:>4} records"
                f"   skipped {len(result.get('skipped', [])):>2}"
                f"   sha256 {result['output_sha256'][:12]}..."
            ),
        )
        for host, derived in loaded["derived"].items():
            unwrapped, extracted = derived["decode"], derived["indicators"]
            print(
                f"  {host}  {'decode.unwrap':<16} {unwrapped['payloads']:>4} payloads"
                f"   from {unwrapped['blobs']} blob(s) across {unwrapped['stages']} stage(s)"
            )
            print(
                f"  {host}  {'indicators':<16} {extracted['indicators']:>4} indicators"
                f"   {extracted['in_execution_context']} of them in something that executed"
            )
        total_records = len(store.query_records())
        print(f"\n  {total_records} records in the case, across {len(casefile.HOSTS)} hosts.")

        rule("CORPUS  claims whose truth is known before the gate sees them")
        built = corpus.build(store, ROOT / "fixtures")
        for problem in built.problems:
            print(f"  PROBLEM  {problem}")
        sound = [c for c in built.cases if c.truth == corpus.SOUND]
        mistaken = [c for c in built.cases if c.truth == corpus.MISTAKEN]
        print(
            f"  {len(built.cases)} cases across {len(corpus.CLASSES)} classes:"
            f" {len(sound)} that should be admitted, {len(mistaken)} that should not."
        )
        print(
            "  Every value claimed below was read off the captured tool output, not\n"
            "  asked of the record it is checked against - otherwise a parser that\n"
            "  mis-read a column would grade its own mistake as correct."
        )

        rule("RUN")
        started = time.monotonic()
        outcomes = [corpus.judge(store, case) for case in built.cases]
        elapsed = time.monotonic() - started
        print(f"  {len(outcomes)} claims submitted in {elapsed:.1f}s")

        admitted_sound = [o for o in outcomes if o.admitted and o.case.truth == corpus.SOUND]
        admitted_mistaken = [o for o in outcomes if o.admitted and o.case.truth == corpus.MISTAKEN]
        refused_sound = [o for o in outcomes if not o.admitted and o.case.truth == corpus.SOUND]
        refused_mistaken = [
            o for o in outcomes if not o.admitted and o.case.truth == corpus.MISTAKEN
        ]

        rule("RESULT")
        print("                          admitted   refused")
        print(f"    evidence supports it  {len(admitted_sound):>8}  {len(refused_sound):>8}")
        print(f"    evidence does not     {len(admitted_mistaken):>8}  {len(refused_mistaken):>8}")
        admitted = len(admitted_sound) + len(admitted_mistaken)
        print()
        print(
            f"    precision  {pct(len(admitted_sound), admitted)}"
            f"   of {admitted} admitted findings, {len(admitted_sound)} were supported"
        )
        print(
            f"    recall     {pct(len(admitted_sound), len(sound))}"
            f"   of {len(sound)} supported claims, {len(admitted_sound)} were admitted"
        )
        right = [o for o in refused_mistaken if o.right_reason]
        print(
            f"    reason     {pct(len(right), len(refused_mistaken))}"
            f"   of {len(refused_mistaken)} refusals, {len(right)} named the actual defect"
        )
        print(
            "\n  The third line is the one that separates accuracy from luck. A claim\n"
            "  stopped for a reason that is not the reason it is wrong was stopped by\n"
            "  accident, and an accident does not repeat on the case you have not seen."
        )

        rule("BY CLASS")
        for error_class in corpus.CLASSES:
            cases = built.by_class(error_class.name)
            got = [o for o in outcomes if o.case.error_class == error_class.name]
            correct = sum(1 for o in got if o.correct)
            reasons = [o for o in got if o.right_reason is not None]
            named = sum(1 for o in reasons if o.right_reason)
            tail = f"  reason {named}/{len(reasons)}" if reasons else ""
            mark = "  " if correct == len(got) else "!!"
            print(
                f"  {mark} {error_class.name:<36} {error_class.expect:<7}"
                f" {correct:>4}/{len(cases):<4}{tail}"
            )
            print(f"       {error_class.description}")

        wrong = [o for o in outcomes if not o.correct]
        misnamed = [o for o in refused_mistaken if o.right_reason is False]
        rule("WHAT CAME OUT WRONG")
        if not wrong and not misnamed:
            print("  Nothing. Every case landed on the side its label says it should.")
        for outcome in wrong:
            verdict = "admitted a false claim" if outcome.admitted else "refused a true claim"
            print(f"  {verdict}  [{outcome.case.error_class}] {outcome.case.name}")
            print(f"      {outcome.case.claim}")
            if outcome.reason:
                print(f"      {outcome.reason}")
        for outcome in misnamed:
            print(f"  right answer, wrong reason  [{outcome.case.error_class}] {outcome.case.name}")
            print(f"      expected the refusal to mention {outcome.case.marker!r}")
            print(f"      got: {outcome.reason}")

        rule("WHAT THE PERCENTAGES CANNOT SEE")
        print(
            "  Supported by this evidence and true about this intrusion are two\n"
            "  different axes, and only the first one is scored above. Where they\n"
            "  come apart on this case:\n"
        )
        for line in KNOWN_MISSES:
            wrapped = textwrap.wrap(line, width=74, initial_indent="  - ", subsequent_indent="    ")
            print("\n".join(wrapped) + "\n")

        rule("LEDGER  what the run left behind")
        findings = store.list_findings()
        rejections = store.list_rejections()
        print(f"  {len(findings)} findings admitted")
        print(
            f"  {len(refused_mistaken)} claims refused, recorded as {len(rejections)} entries."
            " A rejection is identified by what it\n  is - the type, the claim, and the reason"
            " it died - so the same claim refused the\n  same way twice is one line rather than"
            " two. Said here because a count that\n  quietly deduplicates is a count that reads"
            " higher than it is."
        )
        print(f"  {len(store.chain_entries())} entries in the audit chain")
        for host in casefile.HOSTS:
            scoped = report.build(store, host=host)
            print(f"  {host}  {scoped.summary}")
        ok, problems = store.verify_chain()
        print(f"  chain intact: {ok}" + ("" if ok else f"  {problems[:3]}"))

        failed = bool(built.problems) or bool(wrong) or bool(misnamed)
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
