"""Structured-response collector: JSON in, addressable records out.

The other collectors in this package read forensic tools. This one reads whatever
answered a question - a reputation service, an EDR query, a ticketing API - and
that is the point of it. The gate is a field comparison against a stored record;
it has never known or cared that the records came from Volatility. Until now the
only way in was a Volatility table or a `strings` dump, which made a general
argument look like a memory-forensics trick.

So this collector does exactly one job, the same job `rawstrings` does: turn a
response into records a claim can bind to, and make no judgement about any of it.
Whether 12 of 70 engines flagging a file means the file is malicious is not a
question this module has an opinion on. Whether the response really said 12 is.

Nesting is the whole difficulty. A binding names one field on one record, so a
value three levels down needs a name: `data.attributes.last_analysis_stats.malicious`.
Every leaf is flattened to its dotted path, list elements included by index, and
the same path language selects which part of a response is the record set.

Two rules here are deliberate and easy to get backwards:

- **Nothing is truncated.** The store keeps the hash of the raw response, not its
  text, so these records are the only copy of what it said. A shortened value
  would let a claim bind to a prefix and verify against evidence that no longer
  exists in full anywhere.
- **An empty container is a leaf, not an absence.** `{"tags": []}` records
  `tags` as `[]`. Dropping it would make "the service reported no tags" and "the
  service was never asked about tags" the same refusal, and they are not.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..store import Store, canonical, sha256_file

# Recorded as the tool call's name: `response.` plus whatever produced the JSON.
# The prefix is what lets replay route a call back here without a registry of
# every API anyone might ever ingest.
TOOL = "response"
TOOL_PREFIX = "response."

SEPARATOR = "."
ROOT = "."


class ParseError(ValueError):
    pass


@dataclass
class ParseResult:
    rows: list[dict]
    skipped: list[str]


def flatten(document: Any) -> tuple[dict, list[str]]:
    """Reduce a nested value to `dotted.path -> leaf`, reporting ambiguity.

    Two different structures can flatten to the same path when a key contains a
    literal separator - `{"a": {"b": 1}, "a.b": 2}` is one record with two values
    called `a.b`. There is no honest way to pick one, and picking silently would
    let a binding verify against a value the claim was not about, so the clash is
    reported and the caller drops the record.
    """
    fields: dict[str, Any] = {}
    problems: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict) and node:
            for key, child in node.items():
                walk(child, f"{path}{SEPARATOR}{key}" if path else str(key))
            return
        if isinstance(node, list) and node:
            for index, child in enumerate(node):
                walk(child, f"{path}{SEPARATOR}{index}" if path else str(index))
            return
        leaf = canonical(node) if isinstance(node, (dict, list)) else node
        if path in fields:
            problems.append(
                f"two values flatten to the same path {path!r} - a key containing"
                f" {SEPARATOR!r} is ambiguous here, and guessing which one a claim"
                " meant is not something this collector does"
            )
            return
        fields[path] = leaf

    walk(document, "")
    return fields, problems


def select(document: Any, records_at: str | None) -> Any:
    """Walk into a response along the same dotted path the fields use."""
    if not records_at or records_at == ROOT:
        return document
    node = document
    walked: list[str] = []
    for segment in records_at.split(SEPARATOR):
        where = SEPARATOR.join(walked) or "the document"
        if isinstance(node, dict):
            if segment not in node:
                available = ", ".join(sorted(node)[:12]) or "nothing"
                raise ParseError(f"{where} has no key {segment!r}; it has: {available}")
            node = node[segment]
        elif isinstance(node, list):
            if not segment.isdigit() or int(segment) >= len(node):
                raise ParseError(
                    f"{where} is a list of {len(node)}; {segment!r} is not an index into it"
                )
            node = node[int(segment)]
        else:
            raise ParseError(
                f"{where} is a {type(node).__name__}, so it cannot be walked into any further"
            )
        walked.append(segment)
    return node


def parse(output_text: str, records_at: str | None = None) -> ParseResult:
    """Parse a captured response into flat records.

    Elements that cannot become a record are reported, never dropped quietly -
    same contract as the Volatility parser, for the same reason.
    """
    try:
        document = json.loads(output_text)
    except ValueError as exc:
        raise ParseError(f"not readable json: {exc}") from exc

    node = select(document, records_at)
    where = records_at if records_at and records_at != ROOT else "the document"

    if isinstance(node, dict):
        items: list[Any] = [node]
    elif isinstance(node, list):
        items = node
    else:
        raise ParseError(
            f"{where} is a {type(node).__name__}, not an object or a list of objects."
            " Point --records-at at the part of the response that holds the records,"
            " or ingest the whole document as one record and bind to the dotted path."
        )

    rows: list[dict] = []
    skipped: list[str] = []
    for index, item in enumerate(items):
        label = f"element {index} of {where}" if isinstance(node, list) else where
        if not isinstance(item, dict):
            skipped.append(
                f"{label} is a {type(item).__name__}, not an object - a record needs named"
                " fields. Ingest the whole document instead and bind to its dotted path."
            )
            continue
        if not item:
            skipped.append(f"{label} is an empty object - there is nothing to bind to")
            continue
        fields, problems = flatten(item)
        if problems:
            skipped.append(f"{label}: {problems[0]}")
            continue
        rows.append(fields)

    return ParseResult(rows=rows, skipped=skipped)


def argv_for(tool: str, kind: str, records_at: str) -> list[str]:
    """The invocation that produced these records, as the chain will keep it.

    An API response has no shell command behind it, so the honest argv is the
    ingest itself. It has to carry `kind` and `records_at` because replay rebuilds
    from the chain alone, and reading the same response at a different path is a
    different set of records.
    """
    return [
        "witness", "ingest",
        "--tool", TOOL,
        "--source", tool,
        "--kind", kind,
        "--records-at", records_at,
    ]


def from_argv(argv: list[str]) -> dict:
    """Recover the ingest options replay needs from a recorded argv."""
    flags = {"--source": "tool", "--kind": "kind", "--records-at": "records_at"}
    out: dict[str, str] = {}
    for flag, name in flags.items():
        if flag not in argv:
            raise ParseError(f"recorded argv is missing {flag}: {argv}")
        out[name] = argv[argv.index(flag) + 1]
    return out


def ingest_capture(
    store: Store,
    *,
    tool: str,
    output_path: str | Path,
    kind: str | None = None,
    records_at: str | None = None,
    host: str | None = None,
    evidence_path: str | None = None,
    evidence_sha256: str | None = None,
) -> dict:
    """Ingest a captured structured response as an auditable tool call plus records.

    `tool` names whatever answered - it becomes `response.<tool>` in the chain,
    and the record kind unless one is given. `evidence_path` is the right place
    for what was asked: the endpoint, query or ticket id the response came back
    from. A response with no record of its question is evidence you cannot go
    and re-ask.
    """
    if not tool or not tool.strip():
        raise ValueError("a structured response has to name whatever produced it")
    tool = tool.strip()
    kind = (kind or tool).strip()
    records_at = (records_at or ROOT).strip() or ROOT

    output_text = Path(output_path).read_text(encoding="utf-8", errors="replace")
    parsed = parse(output_text, records_at)

    tool_call_id = store.add_tool_call(
        tool=TOOL_PREFIX + tool,
        argv=argv_for(tool, kind, records_at),
        mode="replay",
        output_text=output_text,
        host=host,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
    )
    record_ids = store.add_records(tool_call_id, kind, parsed.rows)

    return {
        "tool_call_id": tool_call_id,
        "plugin": TOOL_PREFIX + tool,
        "kind": kind,
        "records": len(record_ids),
        "record_ids": record_ids,
        "skipped": parsed.skipped,
        "output_sha256": store.get_tool_call(tool_call_id)["output_sha256"],
        "capture_sha256": sha256_file(output_path),
    }
