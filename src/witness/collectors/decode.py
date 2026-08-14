"""Deterministic decoder for encoded payloads found in carved evidence.

An agent that reads `FromBase64String("H4sIAAAA...")` and writes "a gzipped
PowerShell stager, probably Empire, beaconing to some C2" has guessed at three
things. Base64 is not an inference and neither is gzip: they decode or they do
not, byte for byte, in the standard library.

So this analyser decodes rather than describes. It reads records already in the
store, unwraps every encoded layer it can, and writes what came out as new
records - each one traceable back through `derived_from` to the capture it was
carved from. Whatever the payload turns out to reference is then ordinary
evidence that a finding can bind to, instead of a claim about an opaque blob.

Nothing here interprets. It does not decide that a payload is malicious, name a
framework, or label an embedded host as C2. It unwraps layers and stops.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from pathlib import Path  # noqa: F401  (kept for symmetry with file collectors)

from ..store import Store, canonical, sha256_text

TOOL = "decode.unwrap"

KIND_COMMAND_LINE = "command_line"
KIND_BLOB = "encoded_blob"
KIND_PAYLOAD = "decoded_payload"

MAX_STAGES = 4
MIN_BLOB_CHARS = 24

# Evidence is attacker-controlled. A 194 KB carved string can be a gzip member
# that inflates to 200 MB, which without a ceiling is 1.7 GB of resident memory,
# half a minute of CPU and a 200 MB row written into the store - from a payload
# an attacker chose to leave in the image. So decoding stops at a byte count
# rather than at the end of the stream, and a payload that hit the ceiling says
# so in its own record instead of looking like a complete one.
MAX_DECODED_BYTES = 8 * 1024 * 1024
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")

# `CommandLine=` is how a process parameter block appears once it has been
# carved out of a raw image. It says this text was a command line, not that we
# know which PID owned it - keep that distinction, downstream checks rely on it.
_COMMAND_LINE = re.compile(r"CommandLine=(.*)$", re.IGNORECASE)

# Base64 as PowerShell actually carries it: a FromBase64String argument, or the
# argument to -EncodedCommand / -enc.
#
# The character class is exactly the base64 alphabet - no whitespace, no stray
# punctuation. That matters more than it looks: a carved line often runs on into
# unrelated prose, and a class permissive enough to swallow the space would then
# splice those words into the blob and decode a payload that never existed.
_BASE64_SOURCES = (
    re.compile(r"""FromBase64String\(\s*["']([A-Za-z0-9+/=]+)""", re.IGNORECASE),
    re.compile(r"""(?:-enc(?:odedcommand)?)\s+["']?([A-Za-z0-9+/=]{24,})""", re.IGNORECASE),
)


def _clean_base64(raw: str) -> str:
    """Drop everything that is not a base64 character, then trim to a whole quad.

    Strings carved from memory are routinely cut mid-token and sometimes carry a
    stray delimiter. Trimming is lossless in the only direction that matters: it
    can shorten what we decode, never invent it.
    """
    cleaned = re.sub(r"[^A-Za-z0-9+/]", "", raw)
    return cleaned[: len(cleaned) - len(cleaned) % 4]


def _decode_bytes(blob: str) -> bytes | None:
    try:
        return base64.b64decode(_clean_base64(blob), validate=True)
    except (binascii.Error, ValueError):
        return None


def _inflate(raw: bytes) -> tuple[bytes, bool, bool]:
    """Inflate a gzip member, keeping whatever completed if the stream is cut short.

    Carved payloads are usually truncated. Returning the partial inflate with
    `truncated=True` is more useful than returning nothing, as long as the
    truncation is on the record.

    Inflation stops at MAX_DECODED_BYTES. Returns (body, truncated, capped) -
    two different reasons for a partial payload that should not read alike. The
    stream was cut by whoever carved the image; the cap was applied here.
    """
    engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = engine.decompress(raw, MAX_DECODED_BYTES)
    except zlib.error:
        return b"", True, False
    capped = bool(engine.unconsumed_tail)
    return out, (capped or not engine.eof), capped


def _as_text(raw: bytes) -> tuple[str, str]:
    """Return (text, content_type). Binary payloads yield their printable runs."""
    printable = sum(1 for byte in raw if 0x20 <= byte <= 0x7E or byte in (9, 10, 13))
    if raw and printable / len(raw) >= 0.85:
        return raw.decode("utf-8", "replace"), "text"
    runs = [match.decode("ascii") for match in _PRINTABLE_RUN.findall(raw)]
    return "\n".join(runs), "binary"


def _find_blobs(text: str) -> list[str]:
    found: list[str] = []
    for pattern in _BASE64_SOURCES:
        for match in pattern.finditer(text):
            candidate = _clean_base64(match.group(1))
            if len(candidate) >= MIN_BLOB_CHARS:
                found.append(candidate)
    return found


def _mark_superseded(blobs: list[str]) -> dict[str, str | None]:
    """Map each blob to the longer blob it is a strict prefix of, if any.

    A `strings` pass over an image routinely yields the same command line seven
    times at seven lengths, each cut at a different page boundary. Decoding all
    seven would report one payload as seven. Only maximal blobs are decoded, and
    the shorter captures stay in the store saying which blob superseded them.
    """
    ordered = sorted(set(blobs), key=len, reverse=True)
    superseded: dict[str, str | None] = {}
    kept: list[str] = []
    for blob in ordered:
        parent = next((longer for longer in kept if longer.startswith(blob)), None)
        superseded[blob] = sha256_text(parent) if parent else None
        if parent is None:
            kept.append(blob)
    return superseded


def unwrap(store: Store, *, host: str | None = None, source_kinds: tuple[str, ...] = ("string_hit",)) -> dict:
    """Decode every encoded payload reachable from records already in the store."""
    sources: list[dict] = []
    for kind in source_kinds:
        sources.extend(store.query_records(kind=kind, host=host))
    if not sources:
        raise ValueError(
            f"nothing to decode: no {' or '.join(source_kinds)} records"
            + (f" for host {host}" if host else "")
            + ". Ingest a capture first."
        )

    command_lines: list[dict] = []
    blob_origin: dict[str, str] = {}  # blob -> source record id
    stage1_blobs: list[str] = []

    for record in sources:
        text = record["fields"].get("text") or ""
        match = _COMMAND_LINE.search(text)
        if match:
            command_lines.append(
                {
                    "text": match.group(1).strip(),
                    "source_record_id": record["record_id"],
                    "source_kind": record["kind"],
                    "sha256": sha256_text(match.group(1).strip()),
                }
            )
        for blob in _find_blobs(text):
            blob_origin.setdefault(blob, record["record_id"])
            stage1_blobs.append(blob)

    blobs: list[dict] = []
    payloads: list[dict] = []

    def process(stage: int, candidates: list[tuple[str, str | None]]) -> None:
        """Decode one layer. `candidates` are (blob, parent blob hash) pairs."""
        if stage > MAX_STAGES or not candidates:
            return
        parent_of = dict(candidates)
        superseded = _mark_superseded([blob for blob, _ in candidates])
        next_stage: list[tuple[str, str | None]] = []
        for blob in sorted(parent_of, key=len, reverse=True):
            blob_sha = sha256_text(blob)
            parent_sha = parent_of[blob]
            raw = _decode_bytes(blob)
            blobs.append(
                {
                    "stage": stage,
                    "blob_sha256": blob_sha,
                    "blob_chars": len(blob),
                    "parent_blob_sha256": parent_sha,
                    "superseded_by": superseded[blob],
                    "source_record_id": blob_origin.get(blob),
                    "magic_hex": raw[:4].hex() if raw else None,
                    "decodable": raw is not None,
                }
            )
            if raw is None or superseded[blob] is not None:
                continue

            if raw[:2] == b"\x1f\x8b":
                body, truncated, capped = _inflate(raw)
                container = "gzip"
            else:
                body, capped = raw[:MAX_DECODED_BYTES], len(raw) > MAX_DECODED_BYTES
                truncated = capped
                container = "base64"
            text, content_type = _as_text(body)
            payloads.append(
                {
                    "stage": stage,
                    "blob_sha256": blob_sha,
                    "container": container,
                    "content_type": content_type,
                    "truncated": truncated,
                    "capped": capped,
                    "decoded_bytes": len(body),
                    "text": text,
                    "sha256": sha256_text(text),
                    "source_record_id": blob_origin.get(blob),
                }
            )
            for nested in _find_blobs(text):
                # Keep pointing at the carved line this whole tower came from,
                # so provenance survives however many layers deep it goes.
                blob_origin.setdefault(nested, blob_origin.get(blob))
                next_stage.append((nested, blob_sha))
        process(stage + 1, next_stage)

    process(1, [(blob, None) for blob in stage1_blobs])

    rows = {
        KIND_COMMAND_LINE: command_lines,
        KIND_BLOB: blobs,
        KIND_PAYLOAD: payloads,
    }
    source_ids = [record["record_id"] for record in sources]
    tool_call_id = store.add_tool_call(
        tool=TOOL,
        argv=["decode", "--unwrap", f"--host={host or 'any'}", f"--from={','.join(source_kinds)}"],
        mode="derived",
        output_text=canonical(rows),
        host=host,
        derived_from=source_ids,
    )

    written: dict[str, list[str]] = {}
    for kind, items in rows.items():
        written[kind] = store.add_records(tool_call_id, kind, items) if items else []

    return {
        "tool_call_id": tool_call_id,
        "tool": TOOL,
        "host": host,
        "sources": len(source_ids),
        "command_lines": len(command_lines),
        "blobs": len(blobs),
        "superseded": sum(1 for b in blobs if b["superseded_by"]),
        "payloads": len(payloads),
        "capped": sum(1 for p in payloads if p["capped"]),
        "stages": max((p["stage"] for p in payloads), default=0),
        "record_ids": written,
    }
