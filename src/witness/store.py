"""Append-only, hash-chained store for tool calls, evidence records and findings.

Nothing here updates or deletes a row. A correction is a new entry (a retraction),
so the chain stays a complete history of what was claimed and when. Every entry
commits to its predecessor, so editing any earlier row breaks every hash after it.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

# ASCII digits only. `\d` matches every decimal digit in Unicode, so `\d+` would
# read "３７２０" as 3720 and let a claim written in fullwidth digits bind to a PID
# it does not look like. This module refuses homoglyph domains for the same
# reason; a homoglyph integer is not different in kind.
_INT_RE = re.compile(r"^-?[0-9]+$")
_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")


def coerce(value: Any) -> Any:
    """Make a claimed value comparable to a parsed one without softening it.

    Numbers written as strings become numbers; hex offsets become integers.
    Nothing else changes - in particular no substring or fuzzy matching.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value).strip()
    if _INT_RE.match(text) and not _padded(text):
        return int(text)
    if _HEX_RE.match(text):
        return int(text, 16)
    return text


def _padded(text: str) -> bool:
    """Is this an identifier that only looks like a number?

    "007" is not the number 7. It is an account id, a zip code, a device tag -
    something whose leading zeroes are part of it. Reading it as 7 would let a
    claim of 7 verify against a record that says "007", which matters now that
    a collector can store a column verbatim instead of typing it at ingest.

    Decimal only. Hex keeps its padding by convention - 0x0e88 really is 0xe88,
    and that is how the tools that emit offsets write them.
    """
    digits = text[1:] if text[:1] == "-" else text
    return len(digits) > 1 and digits[0] == "0"

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
    seq             INTEGER NOT NULL,
    -- Set when this call read records rather than an evidence file: the record
    -- ids it consumed. Keeps a derived record traceable back to the raw capture.
    derived_from    TEXT
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
    subject      TEXT NOT NULL DEFAULT '{}',
    notes        TEXT NOT NULL,
    status       TEXT NOT NULL,
    seq          INTEGER NOT NULL
);

-- Append-only corrections. A retracted finding is never deleted; the retraction
-- sits after it in the chain so the history of what was believed stays readable.
CREATE TABLE IF NOT EXISTS retractions (
    retraction_id TEXT PRIMARY KEY,
    finding_id    TEXT NOT NULL,
    reason        TEXT NOT NULL,
    seq           INTEGER NOT NULL
);

-- What the agent tried to claim and was stopped from claiming. Kept because a
-- report is more trustworthy when you can see what did not make it in.
--
-- The bindings are kept alongside the reason so a rejection can be re-submitted
-- exactly as it was first attempted. A case that cannot replay its refusals only
-- proves half of itself.
CREATE TABLE IF NOT EXISTS rejections (
    rejection_id TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    claim        TEXT NOT NULL,
    reason       TEXT NOT NULL,
    bindings     TEXT NOT NULL DEFAULT '[]',
    subject      TEXT NOT NULL DEFAULT '{}',
    host         TEXT,
    seq          INTEGER NOT NULL
);

-- A report is a claim about the case, so it gets the same treatment as any other
-- claim: hashed, committed to the chain, and re-checkable afterwards. The entry
-- records which chain state the report was issued from, so a report and a store
-- that have drifted apart can be told from a report and a store that agree.
CREATE TABLE IF NOT EXISTS reports (
    report_id     TEXT PRIMARY KEY,
    report_sha256 TEXT NOT NULL,
    chain_head    TEXT NOT NULL,
    summary       TEXT NOT NULL,
    seq           INTEGER NOT NULL
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
        self._migrate()
        self.db.commit()

    def _migrate(self) -> None:
        """Additive-only schema catch-up for stores opened by an older build.

        Only ever adds nullable columns. Chain payloads are never touched, so a
        store written before a column existed still verifies.
        """
        have = {row["name"] for row in self.db.execute("PRAGMA table_info(tool_calls)")}
        if "derived_from" not in have:
            self.db.execute("ALTER TABLE tool_calls ADD COLUMN derived_from TEXT")

        have = {row["name"] for row in self.db.execute("PRAGMA table_info(rejections)")}
        for column, spec in (
            ("bindings", "TEXT NOT NULL DEFAULT '[]'"),
            ("subject", "TEXT NOT NULL DEFAULT '{}'"),
            ("host", "TEXT"),
        ):
            if column not in have:
                self.db.execute(f"ALTER TABLE rejections ADD COLUMN {column} {spec}")

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
        """Recompute every link, then check the store still agrees with it.

        The hash walk alone catches an edit to the chain. It does not catch an
        edit to the tables the chain committed - the queryable copy of a record
        is a separate row from the chain entry that admitted it, and a finding is
        checked against the queryable copy. So both are compared here.
        """
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
        problems.extend(self._cross_check())
        return (not problems), problems

    # What each chain kind committed, and where to find the queryable copy:
    # (chain kind, table, primary key column, payload keys that must still match)
    _COMMITTED = (
        ("record", "records", "record_id", ("kind", "fields")),
        ("tool_call", "tool_calls", "tool_call_id", ("tool", "mode", "host", "output_sha256")),
        ("finding", "findings", "finding_id", ("finding_type", "claim", "bindings", "subject")),
    )

    def _cross_check(self) -> list[str]:
        """Does every queryable row still say what the chain says it said?"""
        problems: list[str] = []
        for kind, table, key, keys in self._COMMITTED:
            # By id, not by entry: a finding submitted twice is one row and two
            # entries, and that is not a discrepancy.
            committed: set[str] = set()
            for row in self.db.execute(
                "SELECT seq, payload FROM chain WHERE kind = ? ORDER BY seq ASC", (kind,)
            ):
                # A payload edited past recognition is corruption to report, not
                # an exception to raise. An integrity check that dies on damaged
                # input is unavailable exactly when it is needed.
                try:
                    payload = json.loads(row["payload"])
                except ValueError:
                    problems.append(f"seq {row['seq']}: {kind} payload is not readable json")
                    continue
                if not isinstance(payload, dict) or key not in payload:
                    problems.append(
                        f"seq {row['seq']}: {kind} payload has no {key!r} - it is not a"
                        f" {kind} entry any more"
                    )
                    continue
                committed.add(payload[key])
                live = self.db.execute(
                    f"SELECT * FROM {table} WHERE {key} = ?", (payload[key],)  # noqa: S608
                ).fetchone()
                if live is None:
                    problems.append(
                        f"seq {row['seq']}: {kind} {payload[key]} is in the chain"
                        f" but no longer in the store"
                    )
                    continue
                for name in keys:
                    if name not in payload:
                        problems.append(
                            f"seq {row['seq']}: {kind} {payload[key]} entry no longer"
                            f" carries {name!r}"
                        )
                        continue
                    stored = live[name]
                    if isinstance(payload[name], (dict, list)):
                        stored = json.loads(stored)
                    if stored != payload[name]:
                        problems.append(
                            f"seq {row['seq']}: {kind} {payload[key]} field {name!r} no longer"
                            f" matches the chain entry that committed it"
                        )
            live_count = self.db.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]  # noqa: S608
            if live_count != len(committed):
                problems.append(
                    f"{table} holds {live_count} row(s) but the chain committed"
                    f" {len(committed)} - a row was added or removed without an entry"
                )
        return problems

    def head(self) -> str:
        return self._head_hash()

    def has_entry(self, entry_hash: str) -> bool:
        """Is this chain state still in the chain? Cutting the tail is invisible
        to the hash walk, so anything holding an older head can notice."""
        return bool(
            self.db.execute(
                "SELECT 1 FROM chain WHERE entry_hash = ? LIMIT 1", (entry_hash,)
            ).fetchone()
        )

    def case_head(self) -> str:
        """The head of the case, ignoring reports written about the case.

        A report quotes the chain state it describes. If it quoted the raw head,
        issuing the report would move that head and no report could ever be
        re-rendered byte for byte. Reports do not change the evidence, so they do
        not change this value - which is what makes the hash of a report a fact
        about the case rather than about the order someone ran the commands in.
        """
        row = self.db.execute(
            "SELECT entry_hash FROM chain WHERE kind != 'report' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else GENESIS

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
        derived_from: list[str] | None = None,
    ) -> str:
        """Record that a tool ran and what it emitted.

        The id is derived from content, not from a clock, so re-ingesting the
        same output on another machine produces the same id.

        `derived_from` is for analysers that read records instead of an evidence
        file. Naming the source records keeps the derivation auditable: anything
        the analyser produces can be walked back to the capture it came from.
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
        if derived_from:
            payload["derived_from"] = sorted(derived_from)
        collected_at = _now()
        seq, _ = self._append("tool_call", payload)
        self.db.execute(
            "INSERT INTO tool_calls (tool_call_id, tool, argv, mode, host, evidence_path,"
            " evidence_sha256, output_sha256, collected_at, seq, derived_from)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                canonical(sorted(derived_from)) if derived_from else None,
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
        """Write parsed rows under a tool call.

        One tool call may emit several kinds - an analyser that unwraps a payload
        produces command lines, blobs and decoded text from the same run - so ids
        are numbered across the whole call and identity is the row's content, not
        its position. Re-running the same collector is then a no-op rather than a
        second copy of the evidence.
        """
        if not self.get_tool_call(tool_call_id):
            raise ValueError(f"no such tool call: {tool_call_id}")

        existing: dict[tuple[str, str], str] = {}
        next_index = 0
        for row in self.db.execute(
            "SELECT record_id, kind, content_hash FROM records WHERE tool_call_id = ?",
            (tool_call_id,),
        ):
            existing[(row["kind"], row["content_hash"])] = row["record_id"]
            next_index += 1

        record_ids: list[str] = []
        for fields in rows:
            content_hash = sha256_text(canonical(fields))
            seen = existing.get((kind, content_hash))
            if seen:
                record_ids.append(seen)
                continue
            record_id = f"{tool_call_id}#{next_index:04d}"
            next_index += 1
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
            existing[(kind, content_hash)] = record_id
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

    def query_records(
        self, kind: str | None = None, where: dict | None = None, host: str | None = None
    ) -> list[dict]:
        """Query parsed records, optionally scoped to one host.

        Host scoping matters: two images in one store must not corroborate each
        other's findings.
        """
        sql = (
            "SELECT r.*, t.host AS host FROM records r"
            " JOIN tool_calls t ON t.tool_call_id = r.tool_call_id"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("r.kind = ?")
            params.append(kind)
        if host is not None:
            clauses.append("t.host IS ?")
            params.append(host)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY r.seq ASC"

        out = []
        for row in self.db.execute(sql, params):
            item = dict(row)
            item["fields"] = json.loads(item["fields"])
            if where and any(
                coerce(item["fields"].get(k)) != coerce(v) for k, v in where.items()
            ):
                continue
            out.append(item)
        return out

    def tool_calls(self, tool: str | None = None, host: str | None = None) -> list[dict]:
        sql = "SELECT * FROM tool_calls"
        clauses: list[str] = []
        params: list[Any] = []
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        if host is not None:
            clauses.append("host IS ?")
            params.append(host)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq ASC"
        return [dict(row) for row in self.db.execute(sql, params)]

    def host_for_record(self, record_id: str) -> str | None:
        row = self.db.execute(
            "SELECT t.host AS host FROM records r JOIN tool_calls t"
            " ON t.tool_call_id = r.tool_call_id WHERE r.record_id = ?",
            (record_id,),
        ).fetchone()
        return row["host"] if row else None

    def provenance(self, record_id: str) -> list[dict]:
        """Walk a record back through every derivation to the raw captures.

        A domain lifted out of a decoded payload is three tool calls away from
        the image it came from. This is how that distance stays visible instead
        of collapsing into "the tool said so".
        """
        chain: list[dict] = []
        seen_calls: set[str] = set()
        seen_records: set[str] = set()
        frontier = [record_id]
        while frontier:
            current = frontier.pop(0)
            if current in seen_records:
                continue
            seen_records.add(current)
            record = self.get_record(current)
            if not record:
                continue
            call = self.get_tool_call(record["tool_call_id"])
            if call and call["tool_call_id"] not in seen_calls:
                seen_calls.add(call["tool_call_id"])
                chain.append(call)
            # A derived record that names the single record it came from is walked
            # through that, not through everything its tool call happened to read.
            # An extractor may sweep four record kinds in one pass; this domain
            # still came from exactly one of them, and a trail that implicates the
            # other three is a wrong answer dressed as thoroughness.
            source = record["fields"].get("source_record_id")
            if source:
                frontier.append(source)
            elif call and call.get("derived_from"):
                frontier.extend(json.loads(call["derived_from"]))
        # Derivation is a graph, not a line - an extractor may read both a raw
        # capture and something derived from it. Order by when each call was
        # written so the walk reads back as history.
        chain.sort(key=lambda call: call["seq"], reverse=True)
        return chain

    # -------------------------------------------------------------- findings

    def add_finding(
        self,
        *,
        finding_type: str,
        claim: str,
        bindings: list[dict],
        notes: list[str],
        subject: dict | None = None,
    ) -> str:
        subject = subject or {}
        finding_id = sha256_text(canonical([finding_type, claim, bindings, subject]))[:12]
        payload = {
            "finding_id": finding_id,
            "finding_type": finding_type,
            "claim": claim,
            "bindings": bindings,
            "subject": subject,
            "notes": notes,
            "status": "accepted",
        }
        seq, _ = self._append("finding", payload)
        self.db.execute(
            "INSERT OR REPLACE INTO findings (finding_id, finding_type, claim, bindings,"
            " subject, notes, status, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding_id,
                finding_type,
                claim,
                canonical(bindings),
                canonical(subject),
                canonical(notes),
                "accepted",
                seq,
            ),
        )
        self.db.commit()
        return finding_id

    def add_retraction(self, *, finding_id: str, reason: str) -> str:
        """Retract an earlier finding. The finding row stays; this supersedes it."""
        if not self.db.execute(
            "SELECT finding_id FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone():
            raise ValueError(f"no such finding: {finding_id}")
        retraction_id = sha256_text(canonical([finding_id, reason]))[:12]
        if self.db.execute(
            "SELECT retraction_id FROM retractions WHERE retraction_id = ?", (retraction_id,)
        ).fetchone():
            return retraction_id
        payload = {"retraction_id": retraction_id, "finding_id": finding_id, "reason": reason}
        seq, _ = self._append("retraction", payload)
        self.db.execute(
            "INSERT INTO retractions (retraction_id, finding_id, reason, seq) VALUES (?, ?, ?, ?)",
            (retraction_id, finding_id, reason, seq),
        )
        self.db.commit()
        return retraction_id

    def add_rejection(
        self,
        *,
        finding_type: str,
        claim: str,
        reason: str,
        bindings: list[dict] | None = None,
        subject: dict | None = None,
        host: str | None = None,
    ) -> str:
        """Record a claim that did not make it in, and why.

        The bindings are stored so the attempt can be made again exactly as it
        was made the first time. The id stays derived from what the rejection
        *is* - the type, the claim and the reason it died - so stores written
        before the attempt was kept still carry the same ids.
        """
        bindings = bindings or []
        subject = subject or {}
        rejection_id = sha256_text(canonical([finding_type, claim, reason]))[:12]
        if self.db.execute(
            "SELECT rejection_id FROM rejections WHERE rejection_id = ?", (rejection_id,)
        ).fetchone():
            return rejection_id
        payload = {
            "rejection_id": rejection_id,
            "finding_type": finding_type,
            "claim": claim,
            "reason": reason,
        }
        if bindings:
            payload["bindings"] = bindings
        if subject:
            payload["subject"] = subject
        if host:
            payload["host"] = host
        seq, _ = self._append("rejection", payload)
        self.db.execute(
            "INSERT INTO rejections (rejection_id, finding_type, claim, reason, bindings,"
            " subject, host, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rejection_id,
                finding_type,
                claim,
                reason,
                canonical(bindings),
                canonical(subject),
                host,
                seq,
            ),
        )
        self.db.commit()
        return rejection_id

    # --------------------------------------------------------------- reports

    def add_report(self, *, report_sha256: str, summary: str) -> dict:
        """Commit a rendered report to the chain it was rendered from.

        Issuing a report appends an entry, which moves the head - so the entry
        records the head the report was issued *from*. That is the value printed
        in the report itself, and the one a later check compares against.
        """
        chain_head = self.case_head()
        report_id = sha256_text(canonical([report_sha256, chain_head]))[:12]
        existing = self.db.execute(
            "SELECT * FROM reports WHERE report_id = ?", (report_id,)
        ).fetchone()
        if existing:
            return dict(existing)
        payload = {
            "report_id": report_id,
            "report_sha256": report_sha256,
            "chain_head": chain_head,
            "summary": summary,
        }
        seq, _ = self._append("report", payload)
        self.db.execute(
            "INSERT INTO reports (report_id, report_sha256, chain_head, summary, seq)"
            " VALUES (?, ?, ?, ?, ?)",
            (report_id, report_sha256, chain_head, summary, seq),
        )
        self.db.commit()
        return {
            "report_id": report_id,
            "report_sha256": report_sha256,
            "chain_head": chain_head,
            "summary": summary,
            "seq": seq,
        }

    def find_report(self, report_sha256: str) -> dict | None:
        """Look up an issued report by the hash of its bytes."""
        row = self.db.execute(
            "SELECT * FROM reports WHERE report_sha256 = ? ORDER BY seq DESC LIMIT 1",
            (report_sha256,),
        ).fetchone()
        return dict(row) if row else None

    def list_reports(self) -> list[dict]:
        return [dict(row) for row in self.db.execute("SELECT * FROM reports ORDER BY seq ASC")]

    def chain_entries(self) -> list[dict]:
        """Every chain entry in order, payload parsed. The case as it happened."""
        out = []
        for row in self.db.execute("SELECT * FROM chain ORDER BY seq ASC"):
            item = dict(row)
            item["payload"] = json.loads(item["payload"])
            out.append(item)
        return out

    def list_retractions(self) -> list[dict]:
        return [dict(row) for row in self.db.execute("SELECT * FROM retractions ORDER BY seq ASC")]

    def list_findings(self, include_retracted: bool = True) -> list[dict]:
        retracted = {
            row["finding_id"]: row["reason"]
            for row in self.db.execute("SELECT finding_id, reason FROM retractions")
        }
        out = []
        for row in self.db.execute("SELECT * FROM findings ORDER BY seq ASC"):
            item = dict(row)
            item["bindings"] = json.loads(item["bindings"])
            item["subject"] = json.loads(item["subject"])
            item["notes"] = json.loads(item["notes"])
            if item["finding_id"] in retracted:
                item["status"] = "retracted"
                item["retraction_reason"] = retracted[item["finding_id"]]
                if not include_retracted:
                    continue
            out.append(item)
        return out

    def list_rejections(self) -> list[dict]:
        out = []
        for row in self.db.execute("SELECT * FROM rejections ORDER BY seq ASC"):
            item = dict(row)
            item["bindings"] = json.loads(item["bindings"])
            item["subject"] = json.loads(item["subject"])
            out.append(item)
        return out
