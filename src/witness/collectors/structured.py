"""Structured-response collector: what a service returned, as addressable records.

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

Not everything answers in JSON. Most EDR and SIEM exports are a header row and
some delimited lines, so `--format` also takes `csv`, `tsv` and `jsonl`. The
format is declared, never sniffed: a delimiter guessed wrong does not fail, it
produces plausible records with the wrong fields, and plausible-and-wrong is the
one outcome this whole repository exists to prevent.

Delimited cells are stored as the text they are, and nothing is converted. A CSV
has no types to preserve; inventing them at ingest would turn "007" into 7 and
lose an account id to a column that looked numeric. The gate coerces both sides
of a comparison instead, so a claim of 70 still binds to a cell reading `70`,
and a claim of 7 does not bind to one reading `007`.
"""

from __future__ import annotations

import csv
import io
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

JSON = "json"
JSONL = "jsonl"
CSV = "csv"
TSV = "tsv"
FORMATS = (JSON, JSONL, CSV, TSV)

# csv: RFC 4180, so quotes are quotes. tsv: quoting off, because a tab cannot
# appear inside a field and quote-processing a tool's tab-separated output
# mangles any value that merely begins with a quote character.
_DIALECTS = {
    CSV: {"delimiter": ",",  "quoting": csv.QUOTE_MINIMAL},
    TSV: {"delimiter": "\t", "quoting": csv.QUOTE_NONE},
}

_BOM = "\ufeff"


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


def parse(output_text: str, records_at: str | None = None, fmt: str = JSON) -> ParseResult:
    """Parse a captured response into flat records, in the format you declare it is."""
    if fmt not in FORMATS:
        raise ParseError(f"unknown format {fmt!r}; known: {', '.join(FORMATS)}")
    if fmt != JSON and records_at and records_at != ROOT:
        raise ParseError(
            f"--records-at is for json, where the records sit somewhere inside one"
            f" document. A {fmt} response is already a sequence of records."
        )
    if fmt == JSONL:
        return _parse_jsonl(output_text)
    if fmt in _DIALECTS:
        return _parse_delimited(output_text, fmt)
    return _parse_json(output_text, records_at)


def _parse_json(output_text: str, records_at: str | None) -> ParseResult:
    """One document. Elements that cannot become a record are reported, never
    dropped quietly - same contract as the Volatility parser, for the same reason."""
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


def _parse_jsonl(output_text: str) -> ParseResult:
    """One JSON value per line. Nesting flattens exactly as it does in a document."""
    rows: list[dict] = []
    skipped: list[str] = []
    for line_no, line in enumerate(output_text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError as exc:
            skipped.append(f"line {line_no}: not readable json: {exc}")
            continue
        if not isinstance(item, dict):
            skipped.append(
                f"line {line_no} is a {type(item).__name__}, not an object -"
                " a record needs named fields"
            )
            continue
        if not item:
            skipped.append(f"line {line_no} is an empty object - there is nothing to bind to")
            continue
        fields, problems = flatten(item)
        if problems:
            skipped.append(f"line {line_no}: {problems[0]}")
            continue
        rows.append(fields)
    return ParseResult(rows=rows, skipped=skipped)


def _parse_delimited(output_text: str, fmt: str) -> ParseResult:
    """A header row names the fields; every later row is a record.

    Cells are stored verbatim. A delimited file carries no types, and converting
    at ingest would be this collector deciding that a column of identifiers is a
    column of numbers. The gate coerces at comparison time instead, which is
    reversible in a way that a lost leading zero is not.

    Anything wrong with the header is fatal, because it is wrong for every row.
    Anything wrong with one row costs that row and is reported.
    """
    reader = csv.reader(io.StringIO(output_text, newline=""), **_DIALECTS[fmt])
    header: list[str] | None = None
    rows: list[dict] = []
    skipped: list[str] = []

    for line_no, cells in enumerate(reader, start=1):
        if not any(cell.strip() for cell in cells):
            continue

        if header is None:
            # A byte-order mark rides on the first cell and turns `id` into a
            # name nothing can bind to, with no error anyone can act on. It is an
            # encoding artefact rather than content, so it goes.
            cells = [cells[0].lstrip(_BOM), *cells[1:]]
            header = [cell.strip() for cell in cells]
            if any(not name for name in header):
                blank = [i for i, name in enumerate(header) if not name]
                raise ParseError(
                    f"the {fmt} header has no name in column(s) {blank} - a field with"
                    " no name is a field no claim can cite"
                )
            duplicates = sorted({name for name in header if header.count(name) > 1})
            if duplicates:
                raise ParseError(
                    f"the {fmt} header names {', '.join(repr(d) for d in duplicates)} more"
                    " than once; a binding to that field would be ambiguous"
                )
            continue

        if len(cells) != len(header):
            skipped.append(
                f"line {line_no}: expected {len(header)} cells, got {len(cells)}:"
                f" {','.join(cells)[:80]!r}"
            )
            continue
        rows.append(dict(zip(header, cells)))

    if header is None:
        raise ParseError(f"the {fmt} capture is empty - there is no header row to name the fields")
    return ParseResult(rows=rows, skipped=skipped)


def argv_for(tool: str, kind: str, records_at: str, fmt: str) -> list[str]:
    """The invocation that produced these records, as the chain will keep it.

    An API response has no shell command behind it, so the honest argv is the
    ingest itself. It has to carry `kind`, `records_at` and `format` because
    replay rebuilds from the chain alone, and the same bytes read at a different
    path, or as a different format, are a different set of records.
    """
    return [
        "witness", "ingest",
        "--tool", TOOL,
        "--source", tool,
        "--kind", kind,
        "--records-at", records_at,
        "--format", fmt,
    ]


def from_argv(argv: list[str]) -> dict:
    """Recover the ingest options replay needs from a recorded argv.

    `--format` is optional on the way in. Stores written before there was more
    than one format do not carry it, and json is what they meant.
    """
    flags = {"--source": "tool", "--kind": "kind", "--records-at": "records_at"}
    out: dict[str, str] = {}
    for flag, name in flags.items():
        if flag not in argv:
            raise ParseError(f"recorded argv is missing {flag}: {argv}")
        out[name] = argv[argv.index(flag) + 1]
    out["fmt"] = argv[argv.index("--format") + 1] if "--format" in argv else JSON
    return out


def ingest_capture(
    store: Store,
    *,
    tool: str,
    output_path: str | Path,
    kind: str | None = None,
    records_at: str | None = None,
    fmt: str = JSON,
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
    fmt = (fmt or JSON).strip()

    output_text = Path(output_path).read_text(encoding="utf-8", errors="replace")
    parsed = parse(output_text, records_at, fmt)

    tool_call_id = store.add_tool_call(
        tool=TOOL_PREFIX + tool,
        argv=argv_for(tool, kind, records_at, fmt),
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
        "format": fmt,
        # Identity is content, so two identical rows are one record. That is right
        # - the second says nothing the first did not - but it makes the count
        # smaller than the file, and a count that quietly shrinks reads as a parse
        # failure to whoever checks it. So both numbers are reported and they add
        # up to the rows that were read.
        "records": len(set(record_ids)),
        "record_ids": record_ids,
        "duplicates": len(parsed.rows) - len(set(record_ids)),
        "skipped": parsed.skipped,
        "output_sha256": store.get_tool_call(tool_call_id)["output_sha256"],
        "capture_sha256": sha256_file(output_path),
    }
