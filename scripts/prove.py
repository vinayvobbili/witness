#!/usr/bin/env python3
"""Slice 1 proof: submit six findings against real base-wkstn-05 evidence.

One is true and every field is cited. Five are the ways an agent goes wrong.
Run it and watch what does and does not reach the ledger.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from witness.collectors.volatility import ingest_capture  # noqa: E402
from witness.store import Store  # noqa: E402
from witness.verify import Binding, submit_finding  # noqa: E402

FIXTURES = ROOT / "fixtures" / "wkstn05"


def rule(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "wkstn05.db")

        rule("INGEST  real Volatility 3 output, base-wkstn-05 (SANS SRL-2018)")
        for tool in ("psscan", "netscan"):
            result = ingest_capture(
                store,
                plugin_name=tool,
                output_path=FIXTURES / f"{tool}.txt",
                host="base-wkstn-05",
                evidence_path="base-wkstn-05-memory.img",
            )
            print(
                f"  {result['plugin']:<18} {result['records']:>4} records"
                f"   output sha256 {result['output_sha256'][:16]}..."
                f"   skipped {len(result['skipped'])}"
            )
        print(f"  chain head         {store.head()[:32]}...")

        def pid_record(pid: int) -> str:
            hits = [r for r in store.query_records(kind="process") if r["fields"]["pid"] == pid]
            return hits[0]["record_id"]

        cases = [
            (
                "TRUE  the actual kill chain, every link bound",
                "suspicious_process_chain",
                "WmiPrvSE.exe (2676) spawned powershell.exe (3920), which spawned "
                "powershell.exe (1332), which spawned rundll32.exe (3720).",
                [
                    Binding(pid_record(2676), "image_file_name", "WmiPrvSE.exe"),
                    Binding(pid_record(3920), "ppid", 2676),
                    Binding(pid_record(1332), "ppid", 3920),
                    Binding(pid_record(3720), "ppid", 1332),
                    Binding(pid_record(3720), "image_file_name", "rundll32.exe"),
                ],
            ),
            (
                "WRONG  transposed parent PID",
                "suspicious_process_chain",
                "rundll32.exe (3720) was spawned by powershell.exe (1233).",
                [Binding(pid_record(3720), "ppid", 1233)],
            ),
            (
                "WRONG  external C2 that no record contains",
                "c2_channel",
                "The host beaconed to external C2 185.220.101.5.",
                [Binding("nonexistent#0001", "foreign_addr", "185.220.101.5")],
            ),
            (
                "WRONG  real record, real tool call, wrong value",
                "process",
                "PID 2676 is malware.exe.",
                [Binding(pid_record(2676), "image_file_name", "malware.exe")],
            ),
            (
                "WRONG  a conclusion with nothing behind it",
                "assertion",
                "This host is compromised.",
                [],
            ),
            (
                "SUBTLE  name fuller than the evidence (14-byte truncation)",
                "process",
                "subject_srv.exe was running as PID 3548.",
                [Binding(pid_record(3548), "image_file_name", "subject_srv.exe")],
            ),
        ]

        accepted = 0
        for title, finding_type, claim, bindings in cases:
            rule(title)
            print(f"claim: {claim}")
            verdict, finding_id = submit_finding(
                store, finding_type=finding_type, claim=claim, bindings=bindings
            )
            print(verdict.report())
            if finding_id:
                accepted += 1
                print(f"  -> ledger {finding_id}")
            else:
                print("  -> nothing written")

        rule("LEDGER")
        for item in store.list_findings():
            print(f"  {item['finding_id']}  [{item['finding_type']}] {item['claim']}")
        ok, problems = store.verify_chain()
        print(f"\n  {accepted} of {len(cases)} submissions accepted")
        print(f"  chain intact: {ok}" + ("" if ok else f"  {problems}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
