"""A complete two-host case, built the way a real run builds one.

Slices 1 to 3 test the gates in isolation. Slice 4 is about the case as a whole -
what it renders to, and whether it can be re-derived - so both of its test files
want the same fully populated store: two hosts, five captures, two derived
analysers, findings that were admitted and claims that were stopped.
"""

from pathlib import Path

import pytest

from witness.collectors import decode, indicators, rawstrings
from witness.collectors.volatility import ingest_capture
from witness.store import Store
from witness.verify import Binding, submit_finding

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

EMBEDDED_C2 = "aaa.stage.9231829.extranet.wagonwheelgifts.com"

CAPTURES = (
    ("base-wkstn-05", "wkstn05", "psscan"),
    ("base-wkstn-05", "wkstn05", "netscan"),
    ("base-wkstn-01", "wkstn01", "netscan"),
    ("base-wkstn-01", "wkstn01", "malfind"),
)


def build_case(path) -> Store:
    """Ingest, derive, then submit four claims - two that hold and two that do not."""
    store = Store(path)
    for host, folder, tool in CAPTURES:
        ingest_capture(
            store,
            plugin_name=tool,
            output_path=FIXTURES / folder / f"{tool}.txt",
            host=host,
            evidence_path=f"{host}-memory.img",
        )
    rawstrings.ingest_capture(
        store,
        output_path=FIXTURES / "wkstn05" / "strings.txt",
        host="base-wkstn-05",
        evidence_path="base-wkstn-05-memory.img",
    )
    decode.unwrap(store, host="base-wkstn-05")
    indicators.extract(store, host="base-wkstn-05")

    def process(pid: int) -> str:
        return store.query_records(kind="process", host="base-wkstn-05", where={"pid": pid})[0][
            "record_id"
        ]

    def indicator(value: str) -> str:
        return store.query_records(
            kind="indicator", host="base-wkstn-05", where={"value": value}
        )[0]["record_id"]

    submit_finding(
        store,
        finding_type="suspicious_process_chain",
        claim=(
            "WmiPrvSE.exe (2676) spawned powershell.exe (3920), which spawned"
            " powershell.exe (1332), which spawned rundll32.exe (3720)."
        ),
        bindings=[
            Binding(process(2676), "image_file_name", "WmiPrvSE.exe"),
            Binding(process(3920), "ppid", 2676),
            Binding(process(1332), "ppid", 3920),
            Binding(process(3720), "ppid", 1332),
            Binding(process(3720), "pid", 3720),
        ],
        subject={"pid": 3720},
    )
    submit_finding(
        store,
        finding_type="malicious_domain",
        claim=f"The in-memory PowerShell stager carries shellcode that beacons to {EMBEDDED_C2}.",
        bindings=[Binding(indicator(EMBEDDED_C2), "value", EMBEDDED_C2)],
        subject={"domain": EMBEDDED_C2},
    )
    submit_finding(
        store,
        finding_type="malicious_domain",
        claim="The host beaconed to external C2 www.venetodns.trade.",
        bindings=[Binding(indicator("www.venetodns.trade"), "value", "www.venetodns.trade")],
        subject={"domain": "www.venetodns.trade"},
    )
    submit_finding(
        store,
        finding_type="suspicious_process_chain",
        claim="rundll32.exe (3720) was spawned by powershell.exe (1233).",
        bindings=[Binding(process(3720), "ppid", 1233)],
        subject={"pid": 3720},
    )
    return store


@pytest.fixture
def case(tmp_path):
    return build_case(tmp_path / "case.db")
