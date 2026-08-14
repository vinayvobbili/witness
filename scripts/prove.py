#!/usr/bin/env python3
"""Both gates, against real evidence from two SANS hosts.

Act I  - gate 1, base-wkstn-05 (compromised): does the cited record say this?
Act II - gate 2, base-wkstn-01 (clean baseline): what would prove this wrong,
         and did anyone look?

Every rejection below is a call the graded find-evil runs had to make by hand.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from witness.collectors.volatility import ingest_capture  # noqa: E402
from witness.store import Store  # noqa: E402
from witness.verify import Binding, revalidate, submit_finding  # noqa: E402

FIXTURES = ROOT / "fixtures"


def rule(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "case.db")

        rule("INGEST  real Volatility 3 output, SANS SRL-2018")
        plan = [
            ("base-wkstn-05", "wkstn05", "psscan", None),
            ("base-wkstn-05", "wkstn05", "netscan", None),
            ("base-wkstn-01", "wkstn01", "netscan", None),
            ("base-wkstn-01", "wkstn01", "malfind", None),
        ]
        for host, folder, tool, name in plan:
            result = ingest_capture(
                store,
                plugin_name=tool,
                output_path=FIXTURES / folder / f"{name or tool}.txt",
                host=host,
                evidence_path=f"{host}-memory.img",
            )
            print(
                f"  {host}  {result['plugin']:<17} {result['records']:>4} records"
                f"   sha256 {result['output_sha256'][:12]}...   skipped {len(result['skipped'])}"
            )
        print("\n  note: windows.malfind ran on base-wkstn-01 and returned zero rows.")
        print("        It was never run on base-wkstn-05. Those are different facts.")
        print(f"  chain head  {store.head()[:40]}...")

        def process(host: str, pid: int) -> str:
            hits = store.query_records(kind="process", host=host, where={"pid": pid})
            return hits[0]["record_id"]

        def endpoint(host: str, **criteria) -> str:
            hits = store.query_records(kind="network_endpoint", host=host, where=criteria)
            return hits[0]["record_id"]

        cases = [
            (
                "I.1  TRUE   the actual kill chain, every link bound",
                "suspicious_process_chain",
                "WmiPrvSE.exe (2676) spawned powershell.exe (3920), which spawned "
                "powershell.exe (1332), which spawned rundll32.exe (3720).",
                [
                    Binding(process("base-wkstn-05", 2676), "image_file_name", "WmiPrvSE.exe"),
                    Binding(process("base-wkstn-05", 3920), "ppid", 2676),
                    Binding(process("base-wkstn-05", 1332), "ppid", 3920),
                    Binding(process("base-wkstn-05", 3720), "ppid", 1332),
                    Binding(process("base-wkstn-05", 3720), "pid", 3720),
                    Binding(process("base-wkstn-05", 3720), "image_file_name", "rundll32.exe"),
                ],
                {"pid": 3720},
            ),
            (
                "I.2  WRONG  transposed parent PID",
                "suspicious_process_chain",
                "rundll32.exe (3720) was spawned by powershell.exe (1233).",
                [Binding(process("base-wkstn-05", 3720), "ppid", 1233)],
                {"pid": 3720},
            ),
            (
                "I.3  WRONG  external C2 that no record contains",
                "external_c2",
                "The host beaconed to external C2 185.220.101.5.",
                [Binding("nonexistent#0001", "foreign_addr", "185.220.101.5")],
                {"foreign_addr": "185.220.101.5"},
            ),
            (
                "I.4  WRONG  real record, real tool call, wrong value",
                "process_present",
                "PID 2676 is malware.exe.",
                [Binding(process("base-wkstn-05", 2676), "image_file_name", "malware.exe")],
                {"pid": 2676},
            ),
            (
                "I.5  WRONG  a conclusion with nothing behind it",
                "observation",
                "This host is compromised.",
                [],
                {},
            ),
            (
                "I.6  SUBTLE name fuller than the evidence (14-byte truncation)",
                "process_present",
                "subject_srv.exe was running as PID 3548.",
                [Binding(process("base-wkstn-05", 3548), "image_file_name", "subject_srv.exe")],
                {"pid": 3548},
            ),
            (
                "II.1 REFUTED  injection claim, malfind ran and is empty",
                "process_injection",
                "svchost.exe (2332) on base-wkstn-01 contains injected code.",
                [Binding(endpoint("base-wkstn-01", pid=2332), "pid", 2332)],
                {"pid": 2332},
            ),
            (
                "II.2 REFUTED  every binding verifies, the conclusion is still wrong",
                "external_c2",
                "svchost.exe beaconed to external C2 at 172.16.4.10:8080.",
                [
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
                {"foreign_addr": "172.16.4.10"},
            ),
            (
                "II.3 GAP      nobody looked - not a pass",
                "process_injection",
                "rundll32.exe (3720) on base-wkstn-05 contains injected code.",
                [Binding(process("base-wkstn-05", 3720), "pid", 3720)],
                {"pid": 3720},
            ),
        ]

        accepted = 0
        for title, finding_type, claim, bindings, subject in cases:
            rule(title)
            print(f"claim: {claim}")
            verdict, finding_id = submit_finding(
                store,
                finding_type=finding_type,
                claim=claim,
                bindings=bindings,
                subject=subject,
            )
            print(verdict.report())
            if finding_id:
                accepted += 1
                print(f"  -> ledger {finding_id}")
            else:
                print("  -> nothing written")

        rule("LEDGER")
        for item in store.list_findings():
            print(f"  {item['status']:<9} {item['finding_id']}  {item['claim']}")

        rule("REJECTED, AND WHY  (a report is worth more when you can see this)")
        for item in store.list_rejections():
            print(f"  [{item['finding_type']}] {item['claim']}")
            print(f"      {item['reason']}")

        rule("SUMMARY")
        print(f"  {accepted} of {len(cases)} submissions accepted")
        print(f"  {len(store.list_rejections())} claims stopped, each with a recorded refutation")
        print(f"  revalidation pass retracted {len(revalidate(store))} further finding(s)")
        ok, problems = store.verify_chain()
        print(f"  chain intact: {ok}" + ("" if ok else f"  {problems}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
