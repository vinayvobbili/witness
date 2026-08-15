"""Colour, tested as the thing it must never do.

Colour is decoration on a tool whose argument is that nothing decorative should
change what a reader is told. So the properties worth holding are not about
which blue it picked:

- with colour off the output is not merely similar to the uncoloured output, it
  is the same bytes;
- the reader's refusal wins over every other signal;
- a painted label occupies exactly the columns an unpainted one does, so the
  alignment a viewer reads the verdict against does not move;
- nothing read out of the evidence is painted at all.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from witness import demo
from witness.style import OFF, Style

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"

ANSI = re.compile(r"\033\[[0-9;]*m")

ROLES = ("heading", "quiet", "admitted", "refused", "warning")


def toured(tmp_path, style):
    tmp_path.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    demo.run(FIXTURES, store_path=tmp_path / "case.db", root=ROOT, out=lines.append, style=style)
    return lines


def test_disabled_is_the_identity_function():
    for role in ROLES:
        assert getattr(OFF, role)("ADMITTED") == "ADMITTED"
    assert OFF.verdict(True, "True") == "True"
    assert OFF.verdict_badge(False, "REFUSED ") == "REFUSED "


def test_the_tour_prints_the_same_bytes_with_colour_off_as_with_no_style(tmp_path):
    """The reason a caller never has to know this feature exists."""

    without = toured(tmp_path / "a", None)
    off = toured(tmp_path / "b", Style(enabled=False))
    assert without == off


def test_colour_adds_escapes_and_removing_them_gives_the_plain_tour_back(tmp_path):
    plain = toured(tmp_path / "a", None)
    painted = toured(tmp_path / "b", Style(enabled=True, rich=True))
    assert painted != plain
    assert any("\033[" in line for line in painted)
    assert [ANSI.sub("", line) for line in painted] == plain


def test_the_readers_refusal_beats_every_other_signal(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "")
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("TERM", "xterm-256color")
    assert not Style.detect("auto").enabled


@pytest.mark.parametrize(
    "env, expected",
    [
        ({"TERM": "dumb"}, False),
        ({"FORCE_COLOR": "1"}, True),
    ],
)
def test_detection_reads_the_environment(monkeypatch, env, expected):
    for name in ("NO_COLOR", "FORCE_COLOR", "TERM"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert Style.detect("auto").enabled is expected


def test_a_stream_that_is_not_a_terminal_is_not_painted(monkeypatch, tmp_path):
    for name in ("NO_COLOR", "FORCE_COLOR"):
        monkeypatch.delenv(name, raising=False)
    with open(tmp_path / "piped", "w") as handle:
        assert not Style.detect("auto", stream=handle).enabled


def test_explicit_modes_ignore_the_terminal(monkeypatch, tmp_path):
    monkeypatch.delenv("NO_COLOR", raising=False)
    with open(tmp_path / "piped", "w") as handle:
        assert Style.detect("always", stream=handle).enabled
        assert not Style.detect("never", stream=handle).enabled


def test_a_painted_label_field_is_still_eight_columns(tmp_path):
    """The verdict is read by position before it is read as a word."""

    for style in (Style(enabled=True, rich=True), Style(enabled=True, rich=False)):
        for accepted, label in ((True, "ADMITTED"), (False, "REFUSED ")):
            painted = style.verdict_badge(accepted, label)
            assert ANSI.sub("", painted) == label
            assert len(ANSI.sub("", painted)) == 8


def test_evidence_values_are_never_painted(tmp_path):
    """A hash, a PID or a domain prints as the bytes the store holds."""

    painted = toured(tmp_path, Style(enabled=True, rich=True))
    for line in painted:
        for value in ("f5490b2ecf5171665eac25eca96b9efc11cb2ce09d665e9cb61b30a83c722072",
                      "www.venetodns.trade", "185.220.101.5", "1233", "1332"):
            if value in ANSI.sub("", line):
                assert value in line, f"a value was painted: {line!r}"


def test_the_falling_back_palette_covers_every_role():
    """A terminal with sixteen colours gets all five roles, not four and a crash."""

    basic = Style(enabled=True, rich=False)
    for role in ROLES:
        assert "\033[" in getattr(basic, role)("x")
