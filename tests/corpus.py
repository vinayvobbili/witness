"""The accuracy corpus: claims whose truth is settled before the gate sees them.

The adversarial suite asks what a hostile string in the image can make this tool
say. This asks something duller and more important: on ordinary analysis, how
often is it right? A tool that refuses everything is unfalsifiable and useless,
so the corpus carries as many claims that ought to be admitted as claims that
ought to be refused, and both halves are scored.

Two rules keep the measurement honest.

**The labels come from the capture text, not from the store.** Every claimed
value here is read off the captured tool output with the small reader below, not
asked of the record it will be checked against. If the corpus asked witness what
a record says and then tested whether witness agreed, a parser that mis-read a
column would generate a claim matching its own mistake and score full marks. The
column-to-field naming is borrowed from the collector, because naming is not
reading; every value is the file's.

**A refusal has to be for the right reason.** Each mistaken class declares a
marker that the recorded refutation must contain. Stopping the right claim by
accident is luck, and luck does not survive a case you have not seen.

One thing this corpus does not measure, said here rather than buried. The labels
are *supported by this evidence* and *not supported by this evidence*, which is
not the same axis as true and false about the world. The clearest case is
`www.venetodns.trade`: it is the intrusion's real command and control, and it is
filed here under a class that expects a refusal, because in the exported captures
it appears in a raw carve and in nothing that ran. Refusing it is right on this
evidence and is still a miss on this case. `docs/ACCURACY.md` lists every gap of
that kind separately, outside the percentages, where it cannot be rounded away.

A note on the size of the numbers this produces. The corpus is classes times
records: an error class is applied to every record it can apply to, so 57
process rows carrying one error class is 57 cases. They are not 57 independent
experiments, and the per-class table in the accuracy report is the honest way to
read the total. What the total does mean is a census - every row of every
capture in this case has been put through the gate.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from witness.casefile import CAPTURES, Capture
from witness.collectors.volatility import PLUGINS
from witness.store import Store
from witness.verify import Binding, submit_finding

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

WKSTN01 = "base-wkstn-01"
WKSTN05 = "base-wkstn-05"

SOUND = "sound"  # this evidence supports the claim, so it should be admitted
MISTAKEN = "mistaken"  # this evidence does not support the claim, so it should not
ADMIT = "admit"
REFUSE = "refuse"


# ------------------------------------------------------- reading the captures


def read_rows(relpath: str, first_column: str, fixtures: Path = FIXTURES) -> list[list[str]]:
    """Split a captured TSV into its rows, without going near witness's parser."""
    text = (fixtures / relpath).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.split("\t")[0].strip() == first_column:
            return [ln.split("\t") for ln in lines[index + 1 :] if ln.strip()]
    raise AssertionError(f"{relpath}: no {first_column!r} header row found")


def read_lines(relpath: str, fixtures: Path = FIXTURES) -> list[tuple[int, str]]:
    """Numbered non-blank lines, the way the raw-strings collector sees them."""
    text = (fixtures / relpath).read_text(encoding="utf-8", errors="replace")
    return [
        (index, line.strip())
        for index, line in enumerate(text.splitlines(), start=1)
        if line.strip()
    ]


def raw_bool(cell: str) -> bool | None:
    """The one converter the corpus cannot avoid writing for itself.

    Everything else is bound as the string the capture holds and compared after
    the store's own coercion, which keeps two implementations in play. Booleans
    cannot go that route: `coerce` leaves "True" a string, and the gate refuses a
    string bound to a boolean field - correctly, since that is how a claimed 1
    would otherwise pass as a claimed True.
    """
    cell = cell.strip()
    if cell in ("", "-", "N/A"):
        return None
    return cell.lower() == "true"


def blank(cell: str) -> bool:
    return cell.strip() in ("", "-", "N/A")


# --------------------------------------------------------------- the case type


@dataclass(frozen=True)
class Case:
    name: str
    error_class: str
    finding_type: str
    claim: str
    bindings: tuple[tuple[str, str, Any], ...]
    subject: dict
    truth: str
    expect: str
    marker: str = ""
    host: str | None = None


@dataclass(frozen=True)
class ErrorClass:
    name: str
    truth: str
    expect: str
    description: str
    build: Callable[["Bench"], list[Case]]
    marker: str = ""


class Bench:
    """A loaded case, plus somewhere to record what could not be lined up.

    A builder that cannot find the record for a row does not skip it quietly.
    It says so, and the accuracy run treats an unresolvable row as a failure -
    a corpus that silently shrinks when the parser breaks would report the
    breakage as a clean sweep.
    """

    def __init__(self, store: Store, fixtures: Path = FIXTURES) -> None:
        self.store = store
        self.fixtures = fixtures
        self.problems: list[str] = []

    def problem(self, message: str) -> None:
        self.problems.append(message)

    def records(self, kind: str, host: str | None) -> list[dict]:
        return self.store.query_records(kind=kind, host=host)

    def aligned(self, capture: Capture) -> list[tuple[list[str], dict]]:
        """Pair each raw row of a capture with the record it became.

        Alignment is by position, which is the strictest available check: a row
        the collector dropped, duplicated or reordered pushes every later pair
        out of step and the census fails loudly instead of measuring nothing.
        """
        plugin = PLUGINS[capture.plugin]
        rows = read_rows(capture.path, plugin.headers[0], self.fixtures)
        rows = [r for r in rows if len(r) >= len(plugin.columns)]
        records = self.records(plugin.kind, capture.host)
        if len(rows) != len(records):
            self.problem(
                f"{capture.host} {capture.tool}: capture has {len(rows)} parseable row(s),"
                f" store has {len(records)} record(s) - the two cannot be lined up"
            )
            return []
        return list(zip(rows, records))


def _capture(host: str, tool: str) -> Capture:
    for capture in CAPTURES:
        if capture.host == host and capture.tool == tool:
            return capture
    raise AssertionError(f"no shipped capture {tool} for {host}")


PSSCAN05 = _capture(WKSTN05, "windows.psscan")
NETSCAN05 = _capture(WKSTN05, "windows.netscan")
NETSCAN01 = _capture(WKSTN01, "windows.netscan")
STRINGS05 = _capture(WKSTN05, "strings")


def _psscan(bench: Bench) -> list[tuple[list[str], dict]]:
    return bench.aligned(PSSCAN05)


def _tag(record: dict) -> str:
    """The row's position in its capture, so two identically named processes
    do not collapse into one case and quietly halve a class."""
    return "#" + record["record_id"].split("#")[-1]


def _column(capture: Capture, field_name: str) -> int:
    plugin = PLUGINS[capture.plugin]
    for index, (_, name, _) in enumerate(plugin.columns):
        if name == field_name:
            return index
    raise AssertionError(f"{capture.tool} has no {field_name} column")


PID = _column(PSSCAN05, "pid")
PPID = _column(PSSCAN05, "ppid")
IMAGE = _column(PSSCAN05, "image_file_name")
FOREIGN_ADDR = _column(NETSCAN05, "foreign_addr")
FOREIGN_PORT = _column(NETSCAN05, "foreign_port")
NET_PID = _column(NETSCAN05, "pid")


# ------------------------------------------------------------- sound: a census


def build_field_census_captured(bench: Bench) -> list[Case]:
    """Every field of every row of every capture, read back and re-asserted."""
    cases: list[Case] = []
    for capture in CAPTURES:
        if capture.plugin is None:
            continue
        plugin = PLUGINS[capture.plugin]
        for row, record in bench.aligned(capture):
            bindings = []
            for cell, (_, field_name, convert) in zip(row, plugin.columns):
                if blank(cell):
                    continue
                value = raw_bool(cell) if convert.__name__ == "_bool" else cell.strip()
                bindings.append((record["record_id"], field_name, value))
            if not bindings:
                continue
            cases.append(
                Case(
                    name=f"{capture.host}:{capture.tool}:{record['record_id']}",
                    error_class="field_census_captured",
                    finding_type="observation",
                    claim=(
                        f"{capture.tool} on {capture.host} recorded this row"
                        f" with {len(bindings)} readable field(s)."
                    ),
                    bindings=tuple(bindings),
                    subject={},
                    truth=SOUND,
                    expect=ADMIT,
                )
            )
    return cases


def build_field_census_strings(bench: Bench) -> list[Case]:
    """The raw-strings capture, line by line, against the file's own lines."""
    lines = read_lines(STRINGS05.path, bench.fixtures)
    records = bench.records("string_hit", WKSTN05)
    if len(lines) != len(records):
        bench.problem(
            f"{WKSTN05} strings: capture has {len(lines)} non-blank line(s),"
            f" store has {len(records)} record(s)"
        )
        return []
    cases = []
    for (line_no, text), record in zip(lines, records):
        cases.append(
            Case(
                name=f"{WKSTN05}:strings:line{line_no}",
                error_class="field_census_strings",
                finding_type="observation",
                claim=f"Line {line_no} of the carved-strings capture reads as recorded.",
                bindings=(
                    (record["record_id"], "line_no", line_no),
                    (record["record_id"], "text", text),
                ),
                subject={},
                truth=SOUND,
                expect=ADMIT,
            )
        )
    return cases


def build_field_census_derived(bench: Bench) -> list[Case]:
    """The collectors that derive rather than parse, round-tripped.

    Weaker than the captured census and labelled as such: these values have no
    source outside this tool, so the most this can show is that what a collector
    wrote is what the gate reads back. It is still worth running - a record the
    gate cannot re-read is a record no finding can ever cite.
    """
    cases = []
    for kind in ("command_line", "encoded_blob", "decoded_payload", "indicator"):
        for record in bench.records(kind, WKSTN05):
            bindings = [
                (record["record_id"], name, value)
                for name, value in sorted(record["fields"].items())
                if value is not None
            ]
            if not bindings:
                continue
            cases.append(
                Case(
                    name=f"{WKSTN05}:{kind}:{record['record_id']}",
                    error_class="field_census_derived",
                    finding_type="observation",
                    claim=f"A {kind} record derived on {WKSTN05} holds the values recorded.",
                    bindings=tuple(bindings),
                    subject={},
                    truth=SOUND,
                    expect=ADMIT,
                )
            )
    return cases


# ------------------------------------------------------- sound: real findings


def build_sound_process_present(bench: Bench) -> list[Case]:
    cases = []
    for row, record in _psscan(bench):
        pid, image = row[PID].strip(), row[IMAGE].strip()
        cases.append(
            Case(
                name=f"process_present:{image}:{pid}{_tag(record)}",
                error_class="sound_process_present",
                finding_type="process_present",
                claim=f"{image} was resident as PID {pid} on {WKSTN05}.",
                bindings=(
                    (record["record_id"], "pid", pid),
                    (record["record_id"], "image_file_name", image),
                ),
                subject={"pid": int(pid)},
                truth=SOUND,
                expect=ADMIT,
            )
        )
    return cases


def build_sound_process_chain(bench: Bench) -> list[Case]:
    """The intrusion's own kill chain, every link bound to a row of psscan."""
    by_pid = {row[PID].strip(): (row, record) for row, record in _psscan(bench)}
    chain = [("2676", "3920"), ("3920", "1332"), ("1332", "3720")]
    if any(child not in by_pid for _, child in chain) or "2676" not in by_pid:
        bench.problem("the wkstn05 kill chain is not present in psscan")
        return []
    bindings = [(by_pid["2676"][1]["record_id"], "image_file_name", "WmiPrvSE.exe")]
    for parent, child in chain:
        bindings.append((by_pid[child][1]["record_id"], "ppid", parent))
    bindings.append((by_pid["3720"][1]["record_id"], "pid", "3720"))
    bindings.append((by_pid["3720"][1]["record_id"], "image_file_name", "rundll32.exe"))
    return [
        Case(
            name="process_chain:wmi_to_rundll32",
            error_class="sound_process_chain",
            finding_type="suspicious_process_chain",
            claim=(
                "WmiPrvSE.exe (2676) spawned powershell.exe (3920), which spawned"
                " powershell.exe (1332), which spawned rundll32.exe (3720)."
            ),
            bindings=tuple(bindings),
            subject={"pid": 3720},
            truth=SOUND,
            expect=ADMIT,
        )
    ]


def build_sound_executed_domain(bench: Bench) -> list[Case]:
    """A domain that is not merely in the image but in something that ran."""
    cases = []
    for record in bench.records("indicator", WKSTN05):
        fields = record["fields"]
        if fields.get("type") != "domain" or not fields.get("execution_context"):
            continue
        value = fields["value"]
        cases.append(
            Case(
                name=f"executed_domain:{value}",
                error_class="sound_executed_domain",
                finding_type="malicious_domain",
                claim=f"The decoded in-memory stager beacons to {value}.",
                bindings=((record["record_id"], "value", value),),
                subject={"domain": value},
                truth=SOUND,
                expect=ADMIT,
            )
        )
    if not cases:
        bench.problem("no domain on wkstn05 appears in an execution context")
    return cases


def build_sound_encoded_payload(bench: Bench) -> list[Case]:
    cases = []
    for record in bench.records("decoded_payload", WKSTN05):
        sha = record["fields"]["blob_sha256"]
        cases.append(
            Case(
                name=f"encoded_payload:{sha[:12]}",
                error_class="sound_encoded_payload",
                finding_type="encoded_payload",
                claim=(
                    f"A stage-{record['fields']['stage']} "
                    f"{record['fields']['container']} payload was resident in memory."
                ),
                bindings=((record["record_id"], "blob_sha256", sha),),
                subject={"blob_sha256": sha},
                truth=SOUND,
                expect=ADMIT,
            )
        )
    return cases


# ------------------------------------------------- sound: documented tolerances


def build_tolerance_case_fold(bench: Bench) -> list[Case]:
    """WMIPRVSE.EXE and WmiPrvSE.exe are the same Windows object."""
    cases = []
    for row, record in _psscan(bench):
        image = row[IMAGE].strip()
        folded = image.upper()
        if folded == image:
            continue
        cases.append(
            Case(
                name=f"case_fold:{image}{_tag(record)}",
                error_class="tolerance_case_fold",
                finding_type="process_present",
                claim=f"{folded} was resident as PID {row[PID].strip()} on {WKSTN05}.",
                bindings=(
                    (record["record_id"], "pid", row[PID].strip()),
                    (record["record_id"], "image_file_name", folded),
                ),
                subject={"pid": int(row[PID].strip())},
                truth=SOUND,
                expect=ADMIT,
            )
        )
    return cases


def build_tolerance_surrounding_space(bench: Bench) -> list[Case]:
    cases = []
    for row, record in _psscan(bench):
        image = row[IMAGE].strip()
        cases.append(
            Case(
                name=f"padded:{image}:{row[PID].strip()}{_tag(record)}",
                error_class="tolerance_surrounding_space",
                finding_type="process_present",
                claim=f"{image} was resident as PID {row[PID].strip()} on {WKSTN05}.",
                bindings=(
                    (record["record_id"], "pid", f"  {row[PID].strip()} "),
                    (record["record_id"], "image_file_name", f"  {image}  "),
                ),
                subject={"pid": int(row[PID].strip())},
                truth=SOUND,
                expect=ADMIT,
            )
        )
    return cases


# ------------------------------------------------- mistaken: gate one, the read


def _transpose(digits: str) -> str | None:
    reversed_ = digits[::-1].lstrip("0") or "0"
    return None if reversed_ == digits else reversed_


def build_transposed_pid(bench: Bench) -> list[Case]:
    cases = []
    for row, record in _psscan(bench):
        pid = row[PID].strip()
        wrong = _transpose(pid)
        if wrong is None:
            continue
        cases.append(
            Case(
                name=f"transposed_pid:{pid}->{wrong}{_tag(record)}",
                error_class="transposed_pid",
                finding_type="process_present",
                claim=f"{row[IMAGE].strip()} was resident as PID {wrong} on {WKSTN05}.",
                bindings=((record["record_id"], "pid", wrong),),
                subject={"pid": int(wrong)},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="record says",
            )
        )
    return cases


def build_misread_image_name(bench: Bench) -> list[Case]:
    """One character dropped from the middle - what eyeballing a dump produces."""
    cases = []
    for row, record in _psscan(bench):
        image = row[IMAGE].strip()
        if len(image) < 5:
            continue
        middle = len(image) // 2
        wrong = image[:middle] + image[middle + 1 :]
        cases.append(
            Case(
                name=f"misread_name:{image}->{wrong}{_tag(record)}",
                error_class="misread_image_name",
                finding_type="process_present",
                claim=f"{wrong} was resident as PID {row[PID].strip()} on {WKSTN05}.",
                bindings=(
                    (record["record_id"], "pid", row[PID].strip()),
                    (record["record_id"], "image_file_name", wrong),
                ),
                subject={"pid": int(row[PID].strip())},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="record says",
            )
        )
    return cases


def build_field_confusion(bench: Bench) -> list[Case]:
    """The parent's PID asserted as the process's own - a real column slip."""
    cases = []
    for row, record in _psscan(bench):
        pid, ppid = row[PID].strip(), row[PPID].strip()
        if pid == ppid or blank(ppid):
            continue
        cases.append(
            Case(
                name=f"field_confusion:{pid}<-{ppid}{_tag(record)}",
                error_class="field_confusion",
                finding_type="process_present",
                claim=f"{row[IMAGE].strip()} was resident as PID {ppid} on {WKSTN05}.",
                bindings=((record["record_id"], "pid", ppid),),
                subject={"pid": int(ppid)},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="record says",
            )
        )
    return cases


def build_truncation_overreach(bench: Bench) -> list[Case]:
    """A name completed past the width the kernel structure actually holds."""
    cases = []
    for row, record in _psscan(bench):
        image = row[IMAGE].strip()
        if len(image) != 14:
            continue
        wrong = image + "e"
        cases.append(
            Case(
                name=f"truncation_overreach:{image}{_tag(record)}",
                error_class="truncation_overreach",
                finding_type="process_present",
                claim=f"{wrong} was resident as PID {row[PID].strip()} on {WKSTN05}.",
                bindings=(
                    (record["record_id"], "pid", row[PID].strip()),
                    (record["record_id"], "image_file_name", wrong),
                ),
                subject={"pid": int(row[PID].strip())},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="14 characters",
            )
        )
    return cases


def build_phantom_record(bench: Bench) -> list[Case]:
    """Citations that look like citations and point at nothing."""
    real = bench.records("process", WKSTN05)
    if not real:
        bench.problem("no process records on wkstn05")
        return []
    tool_call = real[0]["record_id"].split("#")[0]
    shapes = [
        ("absent_tool_call", "000000000000#0000"),
        ("real_call_absent_row", f"{tool_call}#9999"),
        ("no_index", tool_call),
        ("plausible_prose", "psscan row for rundll32"),
    ]
    return [
        Case(
            name=f"phantom_record:{label}",
            error_class="phantom_record",
            finding_type="process_present",
            claim=f"rundll32.exe was resident as PID 3720 on {WKSTN05}.",
            bindings=((rid, "pid", "3720"),),
            subject={"pid": 3720},
            truth=MISTAKEN,
            expect=REFUSE,
            marker="no such record",
        )
        for label, rid in shapes
    ]


def build_dropped_octet(bench: Bench) -> list[Case]:
    """172.16.4.10 read as 172.16.4.1 - the transposition that starts an incident."""
    cases = []
    for capture in (NETSCAN05, NETSCAN01):
        for row, record in bench.aligned(capture):
            addr = row[FOREIGN_ADDR].strip()
            try:
                parsed = ipaddress.IPv4Address(addr)
            except ValueError:
                continue
            wrong = addr[:-1] if len(addr.rsplit(".", 1)[1]) > 1 else addr + "1"
            try:
                ipaddress.IPv4Address(wrong)
            except ValueError:
                continue
            if wrong == str(parsed):
                continue
            cases.append(
                Case(
                    name=f"dropped_octet:{capture.host}:{record['record_id']}:{wrong}",
                    error_class="dropped_octet",
                    finding_type="observation",
                    claim=f"{capture.host} held a connection record for peer {wrong}.",
                    bindings=((record["record_id"], "foreign_addr", wrong),),
                    subject={},
                    truth=MISTAKEN,
                    expect=REFUSE,
                    marker="record says",
                )
            )
    return cases


def build_transposed_port(bench: Bench) -> list[Case]:
    cases = []
    for capture in (NETSCAN05, NETSCAN01):
        for row, record in bench.aligned(capture):
            port = row[FOREIGN_PORT].strip()
            if blank(port) or not port.isdigit():
                continue
            wrong = _transpose(port)
            if wrong is None:
                continue
            cases.append(
                Case(
                    name=f"transposed_port:{capture.host}:{record['record_id']}:{wrong}",
                    error_class="transposed_port",
                    finding_type="observation",
                    claim=f"{capture.host} held a connection record on peer port {wrong}.",
                    bindings=((record["record_id"], "foreign_port", wrong),),
                    subject={},
                    truth=MISTAKEN,
                    expect=REFUSE,
                    marker="record says",
                )
            )
    return cases


# --------------------------------------- mistaken: gate two, the over-reading


def _is_public(addr: str) -> bool | None:
    try:
        parsed = ipaddress.ip_address(addr.strip())
    except ValueError:
        return None
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def build_internal_peer_as_c2(bench: Bench) -> list[Case]:
    """Every peer in this evidence, called external command and control.

    There is not one routable foreign address in either host's connection table.
    So this class is the whole of what the connection tables can support, read
    the way an agent under pressure reads them, and every case of it is wrong.
    """
    cases = []
    for capture in (NETSCAN05, NETSCAN01):
        for row, record in bench.aligned(capture):
            addr = row[FOREIGN_ADDR].strip()
            public = _is_public(addr)
            if public is not False:
                continue
            cases.append(
                Case(
                    name=f"internal_c2:{capture.host}:{record['record_id']}:{addr}",
                    error_class="internal_peer_as_c2",
                    finding_type="external_c2",
                    claim=f"{capture.host} beaconed to external C2 at {addr}.",
                    bindings=((record["record_id"], "foreign_addr", addr),),
                    subject={"foreign_addr": addr},
                    truth=MISTAKEN,
                    expect=REFUSE,
                    marker="peer_is_routable",
                )
            )
    return cases


def build_unaddressable_peer_as_c2(bench: Bench) -> list[Case]:
    """A listening socket's wildcard peer is not a peer at all."""
    cases = []
    for capture in (NETSCAN05, NETSCAN01):
        for row, record in bench.aligned(capture):
            addr = row[FOREIGN_ADDR].strip()
            if blank(addr) or _is_public(addr) is not None:
                continue
            cases.append(
                Case(
                    name=f"wildcard_c2:{capture.host}:{record['record_id']}",
                    error_class="unaddressable_peer_as_c2",
                    finding_type="external_c2",
                    claim=f"{capture.host} beaconed to external C2 at {addr}.",
                    bindings=((record["record_id"], "foreign_addr", addr),),
                    subject={"foreign_addr": addr},
                    truth=MISTAKEN,
                    expect=REFUSE,
                    marker="cannot be evaluated",
                )
            )
    return cases


def build_injection_without_malfind(bench: Bench) -> list[Case]:
    """An injection claim on the host where nobody ran the tool that settles it."""
    cases = []
    for row, record in _psscan(bench):
        pid = row[PID].strip()
        cases.append(
            Case(
                name=f"injection_unasked:{pid}{_tag(record)}",
                error_class="injection_without_malfind",
                finding_type="process_injection",
                claim=f"{row[IMAGE].strip()} ({pid}) on {WKSTN05} contains injected code.",
                bindings=((record["record_id"], "pid", pid),),
                subject={"pid": int(pid)},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="has not been run",
            )
        )
    return cases


def _wkstn01_pids(bench: Bench) -> list[tuple[str, dict]]:
    seen: dict[str, dict] = {}
    for row, record in bench.aligned(NETSCAN01):
        pid = row[NET_PID].strip()
        if blank(pid) or not pid.isdigit() or pid in seen:
            continue
        seen[pid] = record
    return sorted(seen.items(), key=lambda item: int(item[0]))


def build_injection_refuted_by_empty_malfind(bench: Bench) -> list[Case]:
    """The tool ran on this host and found nothing. That is an answer."""
    cases = []
    for pid, record in _wkstn01_pids(bench):
        cases.append(
            Case(
                name=f"injection_refuted:{pid}",
                error_class="injection_refuted_by_empty_malfind",
                finding_type="process_injection",
                claim=f"PID {pid} on {WKSTN01} contains injected code.",
                bindings=((record["record_id"], "pid", pid),),
                subject={"pid": int(pid)},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="no injection_hit row",
            )
        )
    return cases


def build_process_claim_without_listing(bench: Bench) -> list[Case]:
    """A PID seen in a connection record is not a process listing."""
    cases = []
    for pid, record in _wkstn01_pids(bench):
        cases.append(
            Case(
                name=f"process_unlisted:{pid}",
                error_class="process_claim_without_listing",
                finding_type="process_present",
                claim=f"A process was resident as PID {pid} on {WKSTN01}.",
                bindings=((record["record_id"], "pid", pid),),
                subject={"pid": int(pid)},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="has not been run",
            )
        )
    return cases


def _domains(bench: Bench) -> list[dict]:
    return [
        record
        for record in bench.records("indicator", WKSTN05)
        if record["fields"].get("type") == "domain"
    ]


_INTERNAL = (".lan", ".local", ".corp", ".internal", ".intranet", ".test", ".invalid")


def build_internal_domain_as_c2(bench: Bench) -> list[Case]:
    """The corporate mail server sits in a dump looking exactly like a C2."""
    cases = []
    for record in _domains(bench):
        value = record["fields"]["value"]
        if not value.endswith(_INTERNAL):
            continue
        cases.append(
            Case(
                name=f"internal_domain:{value}",
                error_class="internal_domain_as_c2",
                finding_type="malicious_domain",
                claim=f"{value} is attacker-controlled infrastructure.",
                bindings=((record["record_id"], "value", value),),
                subject={"domain": value},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="is_internal_namespace",
            )
        )
    return cases


def build_carved_domain_as_c2(bench: Bench) -> list[Case]:
    """In the image is not the same fact as in something that ran."""
    cases = []
    for record in _domains(bench):
        fields = record["fields"]
        value = fields["value"]
        if fields.get("execution_context") or value.endswith(_INTERNAL):
            continue
        cases.append(
            Case(
                name=f"carved_domain:{value}",
                error_class="carved_domain_as_c2",
                finding_type="malicious_domain",
                claim=f"The host beaconed to external C2 {value}.",
                bindings=((record["record_id"], "value", value),),
                subject={"domain": value},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="execution",
            )
        )
    return cases


def build_undecoded_blob_as_payload(bench: Bench) -> list[Case]:
    """A guess about what a blob contains, made without decoding it."""
    decoded = {
        record["fields"]["blob_sha256"]
        for record in bench.records("decoded_payload", WKSTN05)
    }
    cases = []
    for record in bench.records("encoded_blob", WKSTN05):
        sha = record["fields"]["blob_sha256"]
        if sha in decoded:
            continue
        cases.append(
            Case(
                name=f"undecoded_blob:{sha[:12]}",
                error_class="undecoded_blob_as_payload",
                finding_type="encoded_payload",
                claim=f"The base64 blob {sha[:12]} is a PowerShell Empire stager.",
                bindings=((record["record_id"], "blob_sha256", sha),),
                subject={"blob_sha256": sha},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="decoded_payload",
            )
        )
    return cases


# --------------------------------- mistaken: the claim's own shape is unsound


def build_subject_drift(bench: Bench) -> list[Case]:
    """Bindings that verify perfectly, about a process nobody cited."""
    cases = []
    for row, record in _psscan(bench):
        pid = row[PID].strip()
        drifted = int(pid) + 10000
        cases.append(
            Case(
                name=f"subject_drift:{pid}->{drifted}{_tag(record)}",
                error_class="subject_drift",
                finding_type="process_present",
                claim=f"{row[IMAGE].strip()} was resident as PID {drifted} on {WKSTN05}.",
                bindings=(
                    (record["record_id"], "pid", pid),
                    (record["record_id"], "image_file_name", row[IMAGE].strip()),
                ),
                subject={"pid": drifted},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="not proved by any binding",
            )
        )
    return cases


def build_unbacked_conclusion(bench: Bench) -> list[Case]:
    """The confident sentence with no citation under it."""
    claims = [
        ("compromised", "observation", "This host is compromised."),
        ("apt", "observation", "The activity is consistent with a state-sponsored actor."),
        ("exfil", "observation", "Data was exfiltrated to an external server."),
        ("persistence", "observation", "The attacker established persistence via a run key."),
    ]
    return [
        Case(
            name=f"unbacked:{label}",
            error_class="unbacked_conclusion",
            finding_type=finding_type,
            claim=claim,
            bindings=(),
            subject={},
            truth=MISTAKEN,
            expect=REFUSE,
            marker="at least one record field",
        )
        for label, finding_type, claim in claims
    ]


def build_cross_host_bindings(bench: Bench) -> list[Case]:
    """One finding, evidence from two machines - no host for the checks to use."""
    procs = bench.records("process", WKSTN05)
    peers = bench.records("network_endpoint", WKSTN01)
    cases = []
    for index in range(min(6, len(procs), len(peers))):
        proc, peer = procs[index], peers[index]
        cases.append(
            Case(
                name=f"cross_host:{proc['record_id']}+{peer['record_id']}",
                error_class="cross_host_bindings",
                finding_type="observation",
                claim="A process on one host is responsible for a connection on another.",
                bindings=(
                    (proc["record_id"], "pid", proc["fields"]["pid"]),
                    (peer["record_id"], "pid", peer["fields"]["pid"]),
                ),
                subject={},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="more than one host",
            )
        )
    if not cases:
        bench.problem("not enough records on both hosts to build cross-host cases")
    return cases


def build_host_mismatch(bench: Bench) -> list[Case]:
    """A finding that names the wrong machine in its own header."""
    cases = []
    for row, record in _psscan(bench)[:6]:
        pid = row[PID].strip()
        cases.append(
            Case(
                name=f"host_mismatch:{pid}{_tag(record)}",
                error_class="host_mismatch",
                finding_type="process_present",
                claim=f"{row[IMAGE].strip()} was resident as PID {pid} on {WKSTN01}.",
                bindings=((record["record_id"], "pid", pid),),
                subject={"pid": int(pid)},
                truth=MISTAKEN,
                expect=REFUSE,
                marker="declares host",
                host=WKSTN01,
            )
        )
    return cases


def build_unregistered_finding_type(bench: Bench) -> list[Case]:
    """A conclusion no check knows how to try to disprove."""
    procs = bench.records("process", WKSTN05)
    if not procs:
        return []
    record = procs[0]
    pid = record["fields"]["pid"]
    return [
        Case(
            name=f"unregistered_type:{name}",
            error_class="unregistered_finding_type",
            finding_type=name,
            claim=f"PID {pid} exhibits {name.replace('_', ' ')}.",
            bindings=((record["record_id"], "pid", pid),),
            subject={"pid": pid},
            truth=MISTAKEN,
            expect=REFUSE,
            marker="no falsification rule",
        )
        for name in ("rootkit_present", "lateral_movement", "data_staging")
    ]


# ------------------------------------------------------------------- the index


CLASSES: tuple[ErrorClass, ...] = (
    ErrorClass(
        "field_census_captured",
        SOUND,
        ADMIT,
        "every field of every parsed row of every capture, re-asserted from the capture text",
        build_field_census_captured,
    ),
    ErrorClass(
        "field_census_strings",
        SOUND,
        ADMIT,
        "every non-blank line of the raw-strings capture, by line number and text",
        build_field_census_strings,
    ),
    ErrorClass(
        "field_census_derived",
        SOUND,
        ADMIT,
        "every field of every derived record, round-tripped (no source outside this tool)",
        build_field_census_derived,
    ),
    ErrorClass(
        "sound_process_present",
        SOUND,
        ADMIT,
        "each process in the listing, claimed as present",
        build_sound_process_present,
    ),
    ErrorClass(
        "sound_process_chain",
        SOUND,
        ADMIT,
        "the intrusion's kill chain, every link bound",
        build_sound_process_chain,
    ),
    ErrorClass(
        "sound_executed_domain",
        SOUND,
        ADMIT,
        "a domain recovered from something that executed, claimed as C2",
        build_sound_executed_domain,
    ),
    ErrorClass(
        "sound_encoded_payload",
        SOUND,
        ADMIT,
        "a payload claim made against a blob this store actually decoded",
        build_sound_encoded_payload,
    ),
    ErrorClass(
        "tolerance_case_fold",
        SOUND,
        ADMIT,
        "the same process name in the wrong case - admitted, with a note in the ledger",
        build_tolerance_case_fold,
    ),
    ErrorClass(
        "tolerance_surrounding_space",
        SOUND,
        ADMIT,
        "the right value with whitespace around it - admitted",
        build_tolerance_surrounding_space,
    ),
    ErrorClass(
        "transposed_pid",
        MISTAKEN,
        REFUSE,
        "a PID with its digits reversed",
        build_transposed_pid,
        "record says",
    ),
    ErrorClass(
        "misread_image_name",
        MISTAKEN,
        REFUSE,
        "a process name with one character dropped",
        build_misread_image_name,
        "record says",
    ),
    ErrorClass(
        "field_confusion",
        MISTAKEN,
        REFUSE,
        "the parent's PID asserted as the process's own",
        build_field_confusion,
        "record says",
    ),
    ErrorClass(
        "truncation_overreach",
        MISTAKEN,
        REFUSE,
        "a name completed past the width the evidence holds",
        build_truncation_overreach,
        "14 characters",
    ),
    ErrorClass(
        "phantom_record",
        MISTAKEN,
        REFUSE,
        "a citation shaped like a citation, pointing at nothing",
        build_phantom_record,
        "no such record",
    ),
    ErrorClass(
        "dropped_octet",
        MISTAKEN,
        REFUSE,
        "an address with an octet mis-read",
        build_dropped_octet,
        "record says",
    ),
    ErrorClass(
        "transposed_port",
        MISTAKEN,
        REFUSE,
        "a port with its digits reversed",
        build_transposed_port,
        "record says",
    ),
    ErrorClass(
        "internal_peer_as_c2",
        MISTAKEN,
        REFUSE,
        "an RFC1918 peer called external command and control",
        build_internal_peer_as_c2,
        "peer_is_routable",
    ),
    ErrorClass(
        "unaddressable_peer_as_c2",
        MISTAKEN,
        REFUSE,
        "a listening socket's wildcard peer called external command and control",
        build_unaddressable_peer_as_c2,
        "cannot be evaluated",
    ),
    ErrorClass(
        "injection_without_malfind",
        MISTAKEN,
        REFUSE,
        "an injection claim on the host where malfind was never run",
        build_injection_without_malfind,
        "has not been run",
    ),
    ErrorClass(
        "injection_refuted_by_empty_malfind",
        MISTAKEN,
        REFUSE,
        "an injection claim on the host where malfind ran and returned nothing",
        build_injection_refuted_by_empty_malfind,
        "no injection_hit row",
    ),
    ErrorClass(
        "process_claim_without_listing",
        MISTAKEN,
        REFUSE,
        "a process claim on a host with no process listing ingested",
        build_process_claim_without_listing,
        "has not been run",
    ),
    ErrorClass(
        "internal_domain_as_c2",
        MISTAKEN,
        REFUSE,
        "a name that cannot resolve on the internet, called infrastructure",
        build_internal_domain_as_c2,
        "is_internal_namespace",
    ),
    ErrorClass(
        "carved_domain_as_c2",
        MISTAKEN,
        REFUSE,
        "a domain that is in the image but in nothing that ran",
        build_carved_domain_as_c2,
        "execution",
    ),
    ErrorClass(
        "undecoded_blob_as_payload",
        MISTAKEN,
        REFUSE,
        "an assertion about what a blob contains, made without decoding it",
        build_undecoded_blob_as_payload,
        "decoded_payload",
    ),
    ErrorClass(
        "subject_drift",
        MISTAKEN,
        REFUSE,
        "bindings that verify, about a subject none of them proves",
        build_subject_drift,
        "not proved by any binding",
    ),
    ErrorClass(
        "unbacked_conclusion",
        MISTAKEN,
        REFUSE,
        "a confident sentence with no citation under it",
        build_unbacked_conclusion,
        "at least one record field",
    ),
    ErrorClass(
        "cross_host_bindings",
        MISTAKEN,
        REFUSE,
        "one finding drawing evidence from two machines",
        build_cross_host_bindings,
        "more than one host",
    ),
    ErrorClass(
        "host_mismatch",
        MISTAKEN,
        REFUSE,
        "a finding that names a host its evidence did not come from",
        build_host_mismatch,
        "declares host",
    ),
    ErrorClass(
        "unregistered_finding_type",
        MISTAKEN,
        REFUSE,
        "a conclusion no registered check knows how to try to disprove",
        build_unregistered_finding_type,
        "no falsification rule",
    ),
)


@dataclass
class Corpus:
    cases: list[Case] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def by_class(self, name: str) -> list[Case]:
        return [case for case in self.cases if case.error_class == name]


def build(store: Store, fixtures: Path = FIXTURES) -> Corpus:
    """Generate every case, over every record each class can apply to."""
    bench = Bench(store, fixtures)
    cases: list[Case] = []
    for error_class in CLASSES:
        built = error_class.build(bench)
        for case in built:
            if case.error_class != error_class.name:
                bench.problem(f"{case.name} is filed under the wrong class")
        if not built:
            bench.problem(f"{error_class.name} produced no cases")
        cases.extend(built)
    return Corpus(cases=cases, problems=bench.problems)


# ------------------------------------------------------------------ the scoring


@dataclass(frozen=True)
class Outcome:
    case: Case
    admitted: bool
    reason: str
    finding_id: str | None

    @property
    def correct(self) -> bool:
        return self.admitted == (self.case.expect == ADMIT)

    @property
    def right_reason(self) -> bool | None:
        """Whether the refusal named the thing that is actually wrong.

        None when the question does not arise - the claim was admitted, or it
        was a sound claim that should never have been refused in the first
        place. A wrongly refused sound claim is already counted as a miss; there
        is nothing to be gained by asking whether it was missed articulately.
        """
        if self.admitted or self.case.expect == ADMIT:
            return None
        return self.case.marker.lower() in self.reason.lower()


def judge(store: Store, case: Case) -> Outcome:
    """Put one case through the real submission path and record what happened."""
    verdict, finding_id = submit_finding(
        store,
        finding_type=case.finding_type,
        claim=case.claim,
        bindings=[Binding(rid, name, value) for rid, name, value in case.bindings],
        subject=dict(case.subject),
        host=case.host,
    )
    return Outcome(
        case=case,
        admitted=finding_id is not None,
        reason="" if finding_id else verdict.refutation,
        finding_id=finding_id,
    )
