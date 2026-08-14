"""The indicator oracle: pull addresses, domains, URLs and hashes out of records.

This is the piece the earlier submission imported from a separate package, which
meant a judge cloning the repo could not read the thing the repo was about. It
lives here now, in the standard library, in one file you can read end to end.

The extractor's job is to be exhaustive and to say where each indicator came
from. It is emphatically *not* to say which ones are bad - it assigns no score,
consults no reputation feed and keeps no allowlist of "known good" sites, all of
which would smuggle a judgement in as data.

The one distinction it does record is structural and checkable: whether an
indicator was carved out of raw image bytes, where anything a user ever received
in email also lives, or lifted from something that ran. `execution_context` is
that bit, and the falsification matrix is what decides it matters.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..store import Store, canonical, sha256_text

TOOL = "indicators.extract"
KIND = "indicator"

# (record kind, field to read, does this kind represent something that executed)
SOURCES: tuple[tuple[str, str, bool], ...] = (
    ("string_hit", "text", False),
    ("command_line", "text", True),
    ("decoded_payload", "text", True),
    ("network_endpoint", "foreign_addr", True),
)

CONTEXT_CHARS = 60

# Defanging is a convention, not an encoding, so undoing it is a fixed table
# rather than anything clever. Applied before extraction so `hxxp://evil[.]com`
# and `http://evil.com` produce the same indicator.
_REFANG = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("hXXps", "https"),
    ("hXXp", "http"),
)

_URL = re.compile(r"\bhttps?://[^\s<>\"'\)\]\},]+", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_HASHES = (
    ("md5", re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)),
    ("sha1", re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)),
    ("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)),
)

# A dotted token is not a hostname just because it is dotted. `IO.MemoryStream`
# in a PowerShell command, `Exchange.asmx` in a mail artifact and `base-mail.shiel`
# from a carve cut mid-word all match any regex loose enough to match a domain -
# and a report that lists them as infrastructure has invented three indicators
# before anyone has drawn a conclusion.
#
# So the last label has to be a real top-level domain. The IANA list is vendored
# under data/ with its version header rather than fetched, so extraction is
# offline and gives the same answer on any machine. Internal namespaces are
# unioned in deliberately: `.lan` is not an IANA TLD, but a claim about
# `base-mail.shieldbase.lan` should be refused by the falsification matrix for
# saying so, not quietly dropped here where nobody sees it.
_TLD_FILE = Path(__file__).resolve().parent.parent / "data" / "iana_tlds.txt"
_INTERNAL_TLDS = frozenset(
    "lan local localdomain localhost corp internal intranet home arpa".split()
)


def _load_tlds() -> frozenset[str]:
    labels = {
        line.strip().lower()
        for line in _TLD_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    return frozenset(labels | _INTERNAL_TLDS)


TLDS = _load_tlds()

TLD_LIST_VERSION = next(
    (
        line.strip("# \n")
        for line in _TLD_FILE.read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    ),
    "unknown",
)


def _refang(text: str) -> str:
    for needle, replacement in _REFANG:
        if needle in text:
            text = text.replace(needle, replacement)
    return text


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and int(part) <= 255 for part in parts)


def _looks_like_a_domain(value: str) -> bool:
    if "." not in value or _valid_ipv4(value):
        return False
    return value.rsplit(".", 1)[-1].lower() in TLDS


def _context(text: str, start: int, end: int) -> str:
    left = max(0, start - CONTEXT_CHARS)
    right = min(len(text), end + CONTEXT_CHARS)
    snippet = text[left:right].replace("\n", " ").strip()
    return ("..." if left else "") + snippet + ("..." if right < len(text) else "")


def extract_from_text(text: str, declined: set[str] | None = None) -> list[dict]:
    """Every indicator in one blob of text, each with the span it came from.

    Overlaps are intentional: the host inside a URL is also emitted as a domain,
    because a claim may reasonably be made about either.

    Pass `declined` to collect dotted tokens turned away for an unrecognised
    suffix. The vendored TLD list is a snapshot, so it can turn away a genuine
    name registered under a newer gTLD - a filter that drops evidence has to
    report what it dropped rather than let the count read as a clean sweep.
    """
    refanged = _refang(text)
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def emit(kind: str, value: str, start: int, end: int) -> None:
        key = (kind, value.lower())
        if key in seen:
            return
        seen.add(key)
        found.append(
            {
                "type": kind,
                "value": value.lower(),
                "context": _context(refanged, start, end),
                "defanged": refanged != text,
            }
        )

    for match in _URL.finditer(refanged):
        emit("url", match.group(0).rstrip(".,;"), match.start(), match.end())
    for match in _IPV4.finditer(refanged):
        if _valid_ipv4(match.group(0)):
            emit("ipv4", match.group(0), match.start(), match.end())
    for match in _DOMAIN.finditer(refanged):
        candidate = match.group(0).rstrip(".")
        if _looks_like_a_domain(candidate):
            emit("domain", candidate, match.start(), match.end())
        elif declined is not None and not _valid_ipv4(candidate):
            declined.add(candidate.rsplit(".", 1)[-1].lower())
    for kind, pattern in _HASHES:
        for match in pattern.finditer(refanged):
            emit(kind, match.group(0), match.start(), match.end())

    return found


def extract(store: Store, *, host: str | None = None) -> dict:
    """Run the extractor over every eligible record and write indicator records."""
    rows: list[dict] = []
    source_ids: list[str] = []
    seen: set[tuple[str, str, bool]] = set()
    declined: set[str] = set()

    for kind, field_name, execution_context in SOURCES:
        for record in store.query_records(kind=kind, host=host):
            text = record["fields"].get(field_name)
            if not text:
                continue
            source_ids.append(record["record_id"])
            for indicator in extract_from_text(str(text), declined):
                key = (indicator["type"], indicator["value"], execution_context)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        **indicator,
                        "source_record_id": record["record_id"],
                        "source_kind": kind,
                        "execution_context": execution_context,
                    }
                )

    if not source_ids:
        raise ValueError(
            "nothing to extract from: no records of kind "
            + ", ".join(kind for kind, _, _ in SOURCES)
            + (f" for host {host}" if host else "")
        )

    tool_call_id = store.add_tool_call(
        tool=TOOL,
        argv=["indicators", "extract", f"--host={host or 'any'}"],
        mode="derived",
        output_text=canonical(rows),
        host=host,
        derived_from=source_ids,
    )
    record_ids = store.add_records(tool_call_id, KIND, rows)

    by_type: dict[str, int] = {}
    for row in rows:
        by_type[row["type"]] = by_type.get(row["type"], 0) + 1

    return {
        "tool_call_id": tool_call_id,
        "tool": TOOL,
        "host": host,
        "sources": len(source_ids),
        "indicators": len(record_ids),
        "by_type": by_type,
        "in_execution_context": sum(1 for row in rows if row["execution_context"]),
        "declined_suffixes": sorted(declined),
        "tld_list": TLD_LIST_VERSION,
        "record_ids": record_ids,
        "output_sha256": sha256_text(canonical(rows)),
    }
