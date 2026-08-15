#!/usr/bin/env python3
"""Run the whole thing, from a clone, with nothing installed.

    python demo.py

That is the entire setup. No pip, no API key, no 3 GB memory image, no network,
and no dependency outside the standard library. This file exists at the root of
the repository rather than under scripts/ because the first thing someone does
with a repository is look at the root of it.

`witness demo` is the same tour once the package is installed.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

if sys.version_info < (3, 10):  # pragma: no cover - checked before the imports below
    sys.exit(f"witness needs Python 3.10 or newer; this is {sys.version.split()[0]}")

from witness.demo import run  # noqa: E402
from witness.style import Style  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="demo.py", description=__doc__)
    parser.add_argument(
        "--pace",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="pause between beats, for recording a screen capture (default 0)",
    )
    parser.add_argument(
        "--keep",
        metavar="DIR",
        help="keep the store and the replayed copy in DIR instead of a temp dir",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="colour the labels and verdicts; auto means only into a terminal (default auto)",
    )
    args = parser.parse_args(argv)
    style = Style.detect(args.color)

    if args.keep:
        workdir = Path(args.keep)
        workdir.mkdir(parents=True, exist_ok=True)
        tour = run(
            ROOT / "fixtures",
            store_path=workdir / "case.db",
            root=ROOT,
            pace=args.pace,
            style=style,
        )
        print(f"\n  store kept at {workdir / 'case.db'}")
        print(f"  witness --store {workdir / 'case.db'} findings")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            tour = run(
                ROOT / "fixtures",
                store_path=Path(tmp) / "case.db",
                root=ROOT,
                pace=args.pace,
                style=style,
            )

    return 0 if tour.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
