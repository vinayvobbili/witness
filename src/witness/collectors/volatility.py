"""Volatility 3 collectors.

Tool output is parsed into typed records here, once, at ingest. The agent never
sees the raw dump - it queries records. That is what removes the eyeballing step
where transposed octets and mis-read names come from.

Slice 1 implements replay mode: ingest output captured from a real Volatility run,
carrying the evidence hash with it. The parsers are identical either way, so live
mode in a later slice is a thin subprocess wrapper around the same functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..store import Store, sha256_file


class ParseError(ValueError):
    pass


def _text(value: str) -> Any:
    value = value.strip()
    if value in ("", "-", "N/A"):
        return None
    return value


def _int(value: str) -> Any:
    value = value.strip()
    if value in ("", "-", "N/A"):
        return None
    return int(value)


def _hex(value: str) -> Any:
    value = value.strip()
    if value in ("", "-", "N/A"):
        return None
    return int(value, 16)


def _bool(value: str) -> Any:
    value = value.strip()
    if value in ("", "-", "N/A"):
        return None
    return value.lower() == "true"


@dataclass(frozen=True)
class Plugin:
    name: str
    kind: str
    columns: list[tuple[str, str, Callable[[str], Any]]]  # header, field, converter

    @property
    def headers(self) -> list[str]:
        return [h for h, _, _ in self.columns]


PSSCAN = Plugin(
    name="windows.psscan",
    kind="process",
    columns=[
        ("PID", "pid", _int),
        ("PPID", "ppid", _int),
        ("ImageFileName", "image_file_name", _text),
        ("Offset(V)", "offset", _hex),
        ("Threads", "threads", _int),
        ("Handles", "handles", _int),
        ("SessionId", "session_id", _int),
        ("Wow64", "wow64", _bool),
        ("CreateTime", "create_time", _text),
        ("ExitTime", "exit_time", _text),
        ("File output", "file_output", _text),
    ],
)

NETSCAN = Plugin(
    name="windows.netscan",
    kind="network_endpoint",
    columns=[
        ("Offset", "offset", _hex),
        ("Proto", "proto", _text),
        ("LocalAddr", "local_addr", _text),
        ("LocalPort", "local_port", _int),
        ("ForeignAddr", "foreign_addr", _text),
        ("ForeignPort", "foreign_port", _int),
        ("State", "state", _text),
        ("PID", "pid", _int),
        ("Owner", "owner", _text),
        ("Created", "created", _text),
    ],
)

PLUGINS = {"psscan": PSSCAN, "netscan": NETSCAN}


@dataclass
class ParseResult:
    rows: list[dict]
    skipped: list[str]


def parse(plugin: Plugin, output_text: str) -> ParseResult:
    """Parse Volatility's TSV output into typed rows.

    Rows that do not match the header shape are reported, never dropped quietly.
    """
    lines = output_text.splitlines()
    first_column = plugin.headers[0]

    header_index = None
    for index, line in enumerate(lines):
        cells = [c.strip() for c in line.split("\t")]
        if cells and cells[0] == first_column:
            header_index = index
            break
    if header_index is None:
        raise ParseError(f"no {first_column!r} header row found - is this {plugin.name} output?")

    found = [c.strip() for c in lines[header_index].split("\t")]
    if found != plugin.headers:
        raise ParseError(
            f"unexpected {plugin.name} columns.\n  expected: {plugin.headers}\n  found:    {found}"
        )

    rows: list[dict] = []
    skipped: list[str] = []
    for line in lines[header_index + 1 :]:
        if not line.strip():
            continue
        cells = line.split("\t")
        if len(cells) != len(plugin.columns):
            skipped.append(f"expected {len(plugin.columns)} columns, got {len(cells)}: {line[:80]!r}")
            continue
        record: dict = {}
        try:
            for cell, (_, field_name, convert) in zip(cells, plugin.columns):
                record[field_name] = convert(cell)
        except (ValueError, TypeError) as exc:
            skipped.append(f"{exc}: {line[:80]!r}")
            continue
        rows.append(record)

    return ParseResult(rows=rows, skipped=skipped)


def ingest_capture(
    store: Store,
    *,
    plugin_name: str,
    output_path: str | Path,
    host: str | None = None,
    evidence_path: str | None = None,
    evidence_sha256: str | None = None,
) -> dict:
    """Ingest captured Volatility output as an auditable tool call plus records."""
    if plugin_name not in PLUGINS:
        raise ValueError(f"unknown plugin {plugin_name!r}; known: {', '.join(sorted(PLUGINS))}")
    plugin = PLUGINS[plugin_name]

    output_text = Path(output_path).read_text(encoding="utf-8", errors="replace")
    parsed = parse(plugin, output_text)

    argv = ["vol", "-f", evidence_path or "<captured>", plugin.name]
    tool_call_id = store.add_tool_call(
        tool=plugin.name,
        argv=argv,
        mode="replay",
        output_text=output_text,
        host=host,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
    )
    record_ids = store.add_records(tool_call_id, plugin.kind, parsed.rows)

    return {
        "tool_call_id": tool_call_id,
        "plugin": plugin.name,
        "kind": plugin.kind,
        "records": len(record_ids),
        "record_ids": record_ids,
        "skipped": parsed.skipped,
        "output_sha256": store.get_tool_call(tool_call_id)["output_sha256"],
        "capture_sha256": sha256_file(output_path),
    }
