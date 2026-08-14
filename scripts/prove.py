#!/usr/bin/env python3
"""Both gates, against real evidence from two SANS hosts.

Act I   - gate 1, base-wkstn-05 (compromised): does the cited record say this?
Act II  - gate 2, base-wkstn-01 (clean baseline): what would prove this wrong,
          and did anyone look?
Act III - the domain stack: fifteen suspicious-looking names in one image, and
          the difference between a domain that was in RAM and one that ran.
Act IV  - the report, and whether anyone else can get the same one back.

Every rejection below is a call the graded find-evil runs had to make by hand.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from witness import casefile, report  # noqa: E402
from witness.replay import replay  # noqa: E402
from witness.store import Store  # noqa: E402
from witness.verify import Binding, revalidate, submit_finding  # noqa: E402

FIXTURES = ROOT / "fixtures"


def rule(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "case.db")

        rule("INGEST  real Volatility 3 output, SANS SRL-2018")
        loaded = casefile.load(
            store,
            FIXTURES,
            on_capture=lambda capture, result: print(
                f"  {capture.host}  {capture.tool:<17} {result['records']:>4} records"
                f"   sha256 {result['output_sha256'][:12]}..."
                f"   skipped {len(result.get('skipped', []))}"
            ),
        )
        print("\n  note: windows.malfind ran on base-wkstn-01 and returned zero rows.")
        print("        It was never run on base-wkstn-05. Those are different facts.")

        rule("DERIVE  unwrap what is encoded, then extract indicators")
        unwrapped = loaded["derived"]["base-wkstn-05"]["decode"]
        print(
            f"  decode.unwrap      {unwrapped['command_lines']} carved command line(s),"
            f" {unwrapped['blobs']} blob(s) ({unwrapped['superseded']} superseded as"
            f" prefixes of a longer capture)"
        )
        print(
            f"                     {unwrapped['payloads']} payload(s) decoded across"
            f" {unwrapped['stages']} stage(s) - base64, then gzip, then base64 again"
        )
        for record in store.query_records(kind="decoded_payload", host="base-wkstn-05"):
            fields = record["fields"]
            head = fields["text"].splitlines()[0][:58]
            print(
                f"                     stage {fields['stage']}: {fields['container']}"
                f"/{fields['content_type']}, {fields['decoded_bytes']} bytes"
                f"{', truncated' if fields['truncated'] else ''}  {head!r}"
            )
        extracted = loaded["derived"]["base-wkstn-05"]["indicators"]
        by_type = ", ".join(f"{k}={v}" for k, v in sorted(extracted["by_type"].items()))
        print(f"  indicators.extract {extracted['indicators']} indicator(s)  ({by_type})")
        print(
            f"                     {extracted['in_execution_context']} of them appeared in"
            " something that executed; the rest were carved out of raw bytes"
        )
        print(
            "                     declined as non-domains: "
            + ", ".join("." + s for s in extracted["declined_suffixes"][:6])
            + f" (+{max(0, len(extracted['declined_suffixes']) - 6)} more)"
        )
        print(f"  chain head  {store.head()[:40]}...")

        def process(host: str, pid: int) -> str:
            hits = store.query_records(kind="process", host=host, where={"pid": pid})
            return hits[0]["record_id"]

        def endpoint(host: str, **criteria) -> str:
            hits = store.query_records(kind="network_endpoint", host=host, where=criteria)
            return hits[0]["record_id"]

        def indicator(value: str, host: str = "base-wkstn-05") -> str:
            hits = store.query_records(kind="indicator", host=host, where={"value": value})
            return hits[0]["record_id"]

        embedded_c2 = "aaa.stage.9231829.extranet.wagonwheelgifts.com"
        payload = store.query_records(kind="decoded_payload", host="base-wkstn-05")[0]

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
            (
                "III.1 TRUE     the C2 that only exists once you decode for it",
                "malicious_domain",
                "The in-memory PowerShell stager carries shellcode that beacons to "
                f"{embedded_c2}.",
                [Binding(indicator(embedded_c2), "value", embedded_c2)],
                {"domain": embedded_c2},
            ),
            (
                "III.2 UNPROVEN a domain in the image, tied to nothing that ran",
                "malicious_domain",
                "The host beaconed to external C2 www.venetodns.trade.",
                [Binding(indicator("www.venetodns.trade"), "value", "www.venetodns.trade")],
                {"domain": "www.venetodns.trade"},
            ),
            (
                "III.3 REFUTED  the corporate mail server is not infrastructure",
                "malicious_domain",
                "base-mail.shieldbase.lan is attacker-controlled infrastructure.",
                [
                    Binding(
                        indicator("base-mail.shieldbase.lan"),
                        "value",
                        "base-mail.shieldbase.lan",
                    )
                ],
                {"domain": "base-mail.shieldbase.lan"},
            ),
            (
                "III.4 TRUE     the payload claim, made against a payload we decoded",
                "encoded_payload",
                "A gzip-compressed base64 PowerShell payload was resident in memory;"
                " it reflectively loads a second-stage shellcode blob.",
                [
                    Binding(
                        payload["record_id"],
                        "blob_sha256",
                        payload["fields"]["blob_sha256"],
                    )
                ],
                {"blob_sha256": payload["fields"]["blob_sha256"]},
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

        rule("REPORT  rendered from the ledger, re-checking every value on the way")
        built = report.build(store)
        text = report.render_markdown(built)
        entry = report.issue(store, built, text)
        print(f"  {built.summary}")
        print(f"  issued from chain head {entry['chain_head']}")
        print(f"  report sha256          {entry['report_sha256']}")
        print(f"  {len(text.splitlines())} lines, no timestamp anywhere in them - the same case")
        print("  renders the same bytes, so this hash is a fact about the case.")

        rule("REPLAY  rebuild the whole case from the captures alone, then compare")
        print("  Every id here is derived from content, never from a clock or a counter.")
        print("  So a second run over the same captures is the same case or it is not.\n")
        rebuilt = Store(Path(tmp) / "replayed.db")
        outcome = replay(store, [FIXTURES], rebuilt)
        print(outcome.report())

        rule("SUMMARY")
        print(f"  {accepted} of {len(cases)} submissions accepted")
        print(f"  {len(store.list_rejections())} claims stopped, each with a recorded refutation")
        print(f"  revalidation pass retracted {len(revalidate(store))} further finding(s)")
        ok, problems = store.verify_chain()
        print(f"  chain intact: {ok}" + ("" if ok else f"  {problems}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
