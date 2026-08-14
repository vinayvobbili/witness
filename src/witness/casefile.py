"""The case this repository ships with, declared once.

Three things need the same answer to "what evidence is in here, from which host,
and in what order does it load" - the proof script, the accuracy run, and replay.
A list of captures maintained in three places drifts, and a drifted list is the
kind of error this whole project exists to refuse, so it lives here.

The evidence is the SANS SRL-2018 "Compromised Enterprise Network" set:
`base-wkstn-01` (a clean Windows 10 baseline) and `base-wkstn-05` (the Win7 host
with the intrusion on it). The memory images are not in this repository - they
are 3 GB each and not ours to redistribute. What is here is the captured tool
output, carried with the SHA-256 of the image it came from, which is what an
auditor needs to check that a finding matches the tool run that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .collectors import decode, indicators, rawstrings
from .collectors.volatility import ingest_capture
from .store import Store


@dataclass(frozen=True)
class Capture:
    """One tool run, captured, with the host and image it came from."""

    host: str
    tool: str
    path: str  # relative to the fixtures root
    plugin: str | None = None  # Volatility plugin key; None means raw strings

    @property
    def evidence_path(self) -> str:
        return f"{self.host}-memory.img"


CAPTURES: tuple[Capture, ...] = (
    Capture("base-wkstn-01", "windows.info", "wkstn01/info.txt", "info"),
    Capture("base-wkstn-01", "windows.netscan", "wkstn01/netscan.txt", "netscan"),
    Capture("base-wkstn-01", "windows.malfind", "wkstn01/malfind.txt", "malfind"),
    Capture("base-wkstn-05", "windows.psscan", "wkstn05/psscan.txt", "psscan"),
    Capture("base-wkstn-05", "windows.netscan", "wkstn05/netscan.txt", "netscan"),
    Capture("base-wkstn-05", "strings", "wkstn05/strings.txt"),
)

# Hosts whose captures carry something encoded worth unwrapping. Running the
# derived collectors on a host with no strings capture would be a tool call that
# could not have found anything, and an empty tool call in the ledger reads like
# a question that was asked when it was not.
DERIVED_HOSTS: tuple[str, ...] = ("base-wkstn-05",)

HOSTS: tuple[str, ...] = ("base-wkstn-01", "base-wkstn-05")


def ingest(store: Store, capture: Capture, fixtures: Path) -> dict:
    path = Path(fixtures) / capture.path
    if capture.plugin is None:
        return rawstrings.ingest_capture(
            store,
            output_path=path,
            host=capture.host,
            evidence_path=capture.evidence_path,
        )
    return ingest_capture(
        store,
        plugin_name=capture.plugin,
        output_path=path,
        host=capture.host,
        evidence_path=capture.evidence_path,
    )


def load(
    store: Store,
    fixtures: Path,
    *,
    on_capture: Callable[[Capture, dict], None] | None = None,
) -> dict[str, Any]:
    """Ingest every shipped capture, then run the derived collectors.

    Returns the per-step results. Ids are content-derived, so the order below
    changes the chain but not a single record id - two loads of the same
    captures are the same case whichever way round they went in.
    """
    captures: list[tuple[Capture, dict]] = []
    for capture in CAPTURES:
        result = ingest(store, capture, fixtures)
        captures.append((capture, result))
        if on_capture:
            on_capture(capture, result)

    derived: dict[str, dict] = {}
    for host in DERIVED_HOSTS:
        derived[host] = {
            "decode": decode.unwrap(store, host=host),
            "indicators": indicators.extract(store, host=host),
        }

    return {"captures": captures, "derived": derived}
