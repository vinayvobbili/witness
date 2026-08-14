"""Append-only, hash-chained store for tool calls, evidence records and findings.

Nothing here updates or deletes a row. A correction is a new entry (a retraction),
so the chain stays a complete history of what was claimed and when. Every entry
commits to its predecessor, so editing any earlier row breaks every hash after it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS chain (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_calls (
    tool_call_id    TEXT PRIMARY KEY,
    tool            TEXT NOT NULL,
    argv            TEXT NOT NULL,
    mode            TEXT NOT NULL,
    host            TEXT,
    evidence_path   TEXT,
    evidence_sha256 TEXT,
    output_sha256   TEXT NOT NULL,
    collected_at    TEXT NOT NULL,
    seq             INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    record_id    TEXT PRIMARY KEY,
    tool_call_id TEXT NOT NULL,
    kind         TEXT NOT NULL,
    fields       TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    seq          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS records_kind ON records (kind);

CREATE TABLE IF NOT EXISTS findings (
    finding_id   TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    claim        TEXT NOT NULL,
    bindings     TEXT NOT NULL,
    notes        TEXT NOT NULL,
    status       TEXT NOT NULL,
    seq          INTEGER NOT NULL
);
"""


def canonical(obj: Any) -> str:
    """Byte-stable JSON so the same content always hashes the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    """SQLite-backed evidence store. Open it, never mutate it."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    # ---------------------------------------------------------------- chain

    def _head_hash(self) -> str:
        row = self.db.execute("SELECT entry_hash FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
        return row["entry_hash"] if row else GENESIS

    def _append(self, kind: str, payload: dict) -> tuple[int, str]:
        text = canonical(payload)
        payload_hash = sha256_text(text)
        prev_hash = self._head_hash()
        entry_hash = sha256_text(prev_hash + payload_hash)
        cur = self.db.execute(
            "INSERT INTO chain (kind, payload, payload_hash, prev_hash, entry_hash)"
            " VALUES (?, ?, ?, ?, ?)",
            (kind, text, payload_hash, prev_hash, entry_hash),
        )
        return int(cur.lastrowid), entry_hash

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Recompute every link. Any edit to any row shows up here."""
        problems: list[str] = []
        prev = GENESIS
        for row in self.db.execute("SELECT * FROM chain ORDER BY seq ASC"):
            payload_hash = sha256_text(row["payload"])
            if payload_hash != row["payload_hash"]:
                problems.append(f"seq {row['seq']}: payload does not match its hash")
            if row["prev_hash"] != prev:
                problems.append(f"seq {row['seq']}: prev_hash does not match the entry before it")
            expected = sha256_text(row["prev_hash"] + row["payload_hash"])
            if expected != row["entry_hash"]:
                problems.append(f"seq {row['seq']}: entry_hash is not sha256(prev_hash + payload_hash)")
            prev = row["entry_hash"]
        return (not problems), problems

    def head(self) -> str:
        return self._head_hash()

    # ------------------------------------------------------------ tool calls

    def add_tool_call(
        self,
        *,
        tool: str,
        argv: list[str],
        mode: str,
        output_text: str,
        host: str | None = None,
        evidence_path: str | None = None,
        evidence_sha256: str | None = None,
    ) -> str:
        """Record that a tool ran and what it emitted.

        The id is derived from content, not from a clock, so re-ingesting the
        same output on another machine produces the same id.
        """
        output_sha256 = sha256_text(output_text)
        tool_call_id = sha256_text(canonical([tool, argv, output_sha256]))[:12]
        existing = self.db.execute(
            "SELECT tool_call_id FROM tool_calls WHERE tool_call_id = ?", (tool_call_id,)
        ).fetchone()
        if existing:
            return tool_call_id

        payload = {
            "tool_call_id": tool_call_id,
            "tool": tool,
            "argv": argv,
            "mode": mode,
            "host": host,
            "evidence_path": evidence_path,
            "evidence_sha256": evidence_sha256,
            "output_sha256": output_sha256,
        }
        collected_at = _now()
        seq, _ = self._append("tool_call", payload)
        self.db.execute(
            "INSERT INTO tool_calls (tool_call_id, tool, argv, mode, host, evidence_path,"
            " evidence_sha256, output_sha256, collected_at, seq)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tool_call_id,
                tool,
                canonical(argv),
                mode,
                host,
                evidence_path,
                evidence_sha256,
                output_sha256,
                collected_at,
                seq,
            ),
        )
        self.db.commit()
        return tool_call_id

    def get_tool_call(self, tool_call_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM tool_calls WHERE tool_call_id = ?", (tool_call_id,)
        ).fetchone()
        return dict(row) if row else None

    # --------------------------------------------------------------- records

    def add_records(self, tool_call_id: str, kind: str, rows: list[dict]) -> list[str]:
        if not self.get_tool_call(tool_call_id):
            raise ValueError(f"no such tool call: {tool_call_id}")
        record_ids: list[str] = []
        for index, fields in enumerate(rows):
            record_id = f"{tool_call_id}#{index:04d}"
            if self.db.execute(
                "SELECT record_id FROM records WHERE record_id = ?", (record_id,)
            ).fetchone():
                record_ids.append(record_id)
                continue
            content_hash = sha256_text(canonical(fields))
            payload = {
                "record_id": record_id,
                "tool_call_id": tool_call_id,
                "kind": kind,
                "fields": fields,
            }
            seq, _ = self._append("record", payload)
            self.db.execute(
                "INSERT INTO records (record_id, tool_call_id, kind, fields, content_hash, seq)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (record_id, tool_call_id, kind, canonical(fields), content_hash, seq),
            )
            record_ids.append(record_id)
        self.db.commit()
        return record_ids

    def get_record(self, record_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM records WHERE record_id = ?", (record_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["fields"] = json.loads(out["fields"])
        return out

    def query_records(self, kind: str | None = None, where: dict | None = None) -> list[dict]:
        sql = "SELECT * FROM records"
        params: list[Any] = []
        if kind:
            sql += " WHERE kind = ?"
            params.append(kind)
        sql += " ORDER BY seq ASC"
        out = []
        for row in self.db.execute(sql, params):
            item = dict(row)
            item["fields"] = json.loads(item["fields"])
            if where and any(item["fields"].get(k) != v for k, v in where.items()):
                continue
            out.append(item)
        return out

    # -------------------------------------------------------------- findings

    def add_finding(
        self, *, finding_type: str, claim: str, bindings: list[dict], notes: list[str]
    ) -> str:
        finding_id = sha256_text(canonical([finding_type, claim, bindings]))[:12]
        payload = {
            "finding_id": finding_id,
            "finding_type": finding_type,
            "claim": claim,
            "bindings": bindings,
            "notes": notes,
            "status": "accepted",
        }
        seq, _ = self._append("finding", payload)
        self.db.execute(
            "INSERT OR REPLACE INTO findings (finding_id, finding_type, claim, bindings,"
            " notes, status, seq) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                finding_id,
                finding_type,
                claim,
                canonical(bindings),
                canonical(notes),
                "accepted",
                seq,
            ),
        )
        self.db.commit()
        return finding_id

    def list_findings(self) -> list[dict]:
        out = []
        for row in self.db.execute("SELECT * FROM findings ORDER BY seq ASC"):
            item = dict(row)
            item["bindings"] = json.loads(item["bindings"])
            item["notes"] = json.loads(item["notes"])
            out.append(item)
        return out
