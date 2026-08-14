from pathlib import Path

import pytest

from witness.collectors.volatility import NETSCAN, PSSCAN, ParseError, parse

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "wkstn05"


def read(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_psscan_parses_every_row():
    result = parse(PSSCAN, read("psscan.txt"))
    assert result.skipped == []
    assert len(result.rows) == 57


def test_psscan_types_are_real_types():
    rows = parse(PSSCAN, read("psscan.txt")).rows
    row = next(r for r in rows if r["pid"] == 2676)
    assert row["ppid"] == 776
    assert row["image_file_name"] == "WmiPrvSE.exe"
    assert isinstance(row["offset"], int)
    assert row["offset"] == 0x71CFB00
    assert row["wow64"] is False
    assert row["exit_time"] is None  # "N/A" is absence, not the string "N/A"


def test_psscan_keeps_the_kernel_truncation():
    """Volatility truncates ImageFileName at 14 bytes. We store what it emitted."""
    rows = parse(PSSCAN, read("psscan.txt")).rows
    row = next(r for r in rows if r["pid"] == 3548)
    assert row["image_file_name"] == "subject_srv.ex"
    assert len(row["image_file_name"]) == 14


def test_netscan_parses_every_row():
    result = parse(NETSCAN, read("netscan.txt"))
    assert result.skipped == []
    assert len(result.rows) == 112


def test_netscan_empty_state_is_none_not_shifted():
    """UDP rows have an empty State cell. Splitting must not shift columns."""
    rows = parse(NETSCAN, read("netscan.txt")).rows
    udp = next(r for r in rows if r["offset"] == 0x1253EEC0)
    assert udp["proto"] == "UDPv4"
    assert udp["state"] is None
    assert udp["pid"] == 4600
    assert udp["owner"] == "OUTLOOK.EXE"


def test_netscan_proxy_egress_rows_are_present():
    rows = parse(NETSCAN, read("netscan.txt")).rows
    proxy = [r for r in rows if r["foreign_addr"] == "172.16.4.10" and r["foreign_port"] == 8080]
    assert len(proxy) == 6
    assert all(r["pid"] is None for r in proxy)


def test_wrong_plugin_output_is_an_error_not_empty_rows():
    with pytest.raises(ParseError):
        parse(NETSCAN, read("psscan.txt"))
