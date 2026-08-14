#!/usr/bin/env python3
"""Run every attack in the catalogue and print what held.

A test suite that goes green tells you the number. This prints the argument: for
each family, the invariant being defended, how many ways it was attacked, and
what the attacks were. Same cases as `pytest tests/test_adversarial.py` - the
catalogue is data, and both read it.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from adversarial import families, run  # noqa: E402


def rule(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def main() -> int:
    rule("ADVERSARIAL  what has been tried against this tool, and what held")
    print(
        "  A memory image is not trusted input. Everything in it was writable by\n"
        "  whoever was on the box, and some of it was written by the intruder on\n"
        "  purpose. So the question is not whether this works on honest evidence."
    )

    total = 0
    blocked = 0
    failures = []

    for family in families():
        print(f"\n  {family.name}  ({len(family.attacks)} cases)")
        print(f"    invariant: {family.invariant}")
        held = 0
        for attack in family.attacks:
            outcome = run(attack)
            total += 1
            if outcome.blocked:
                held += 1
                blocked += 1
            else:
                failures.append((attack, outcome))
        mark = "all held" if held == len(family.attacks) else f"{held}/{len(family.attacks)} held"
        print(f"    {mark}")
        for attack in family.attacks:
            print(f"      - {attack.name}")

    rule("SUMMARY")
    print(f"  {total} adversarial cases across {len(families())} families")
    print(f"  {blocked} blocked, {total - blocked} succeeded")
    for attack, outcome in failures:
        print(f"    SUCCEEDED  {attack.family}:{attack.name}  {outcome.detail}")

    print(
        "\n  Seven defects were found by writing this, and are fixed rather than\n"
        "  documented:\n"
        "    - a gzip bomb in a carved string inflated to 200 MB of resident memory\n"
        "    - a newline in an evidence path forged a Findings section in the report\n"
        "    - the chain could be cut at the tail and still verify\n"
        "    - verify-chain raised on a mangled payload instead of reporting it\n"
        "    - a homoglyph domain was dropped in silence, not reported as unreadable\n"
        "    - '３７２０' in fullwidth digits compared equal to the PID 3720\n"
        "    - a claimed 1 bound to a boolean field, because Python says True == 1"
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
