"""Carved-string collector.

`strings` over a raw image is the bluntest instrument in memory forensics and
the one most likely to produce a confident wrong answer: every domain any user
ever received in an email is sitting in the same dump as the C2 the attacker
used, with nothing to tell them apart.

So the collector does exactly one job - turn lines into addressable records -
and makes no judgement at all. Separating a carved string from an executed
command is the falsification matrix's problem, and it needs the two to be
distinguishable record kinds to do it.
"""

from __future__ import annotations

from pathlib import Path

from ..store import Store, sha256_file, sha256_text

TOOL = "strings"
KIND = "string_hit"


def parse(output_text: str) -> list[dict]:
    """One record per non-blank line, numbered from the top of the capture."""
    rows: list[dict] = []
    for index, line in enumerate(output_text.splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        rows.append(
            {
                "line_no": index,
                "text": text,
                "length": len(text),
                "sha256": sha256_text(text),
            }
        )
    return rows


def ingest_capture(
    store: Store,
    *,
    output_path: str | Path,
    host: str | None = None,
    evidence_path: str | None = None,
    evidence_sha256: str | None = None,
    encoding_flag: str = "-e l",
) -> dict:
    """Ingest captured `strings` output as an auditable tool call plus records."""
    output_text = Path(output_path).read_text(encoding="utf-8", errors="replace")
    rows = parse(output_text)

    argv = ["strings", *encoding_flag.split(), evidence_path or "<captured>"]
    tool_call_id = store.add_tool_call(
        tool=TOOL,
        argv=argv,
        mode="replay",
        output_text=output_text,
        host=host,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
    )
    record_ids = store.add_records(tool_call_id, KIND, rows)

    return {
        "tool_call_id": tool_call_id,
        "plugin": TOOL,
        "kind": KIND,
        "records": len(record_ids),
        "record_ids": record_ids,
        "skipped": [],
        "output_sha256": store.get_tool_call(tool_call_id)["output_sha256"],
        "capture_sha256": sha256_file(output_path),
    }
