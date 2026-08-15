"""Colour for the terminal, and the reasons it is allowed to be there.

A tool that prints colour into a pipe has corrupted its own output, and one
that prints it when the reader asked for none has ignored them. So this is off
by default for every caller in the library, and the two entry points a human
actually types - `python demo.py` and `witness demo` - turn it on only when
stdout is a terminal that said it wanted it.

Colour is applied to labels and verdicts, never to a value read out of the
evidence. A hash, a PID, a domain and a claim print as the bytes they are, so
anything a reader might copy out of a recording is what the store holds. The
palette is the one the project's page uses, because a recording of this tour
and the page describing it should not look like two different projects.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# The page palette, moved to a dark terminal: the steels keep their hue and
# gain the lightness they need against a dark ground, and ok/no come off the
# same two accents the page uses for an admitted and a refused finding.
STEEL = (127, 179, 201)
STEEL_DIM = (129, 154, 173)
OK = (63, 191, 127)
NO = (255, 107, 129)
WARN = (232, 178, 58)

# Where a terminal cannot be asked for 24-bit colour, the same five roles in
# the sixteen every terminal has. The user's own theme decides what they look
# like, which is the correct outcome at this fidelity.
BASIC = {STEEL: 96, STEEL_DIM: 36, OK: 92, NO: 91, WARN: 93}


def _supported(stream: object) -> bool:
    """Whether writing escape codes to `stream` is defensible.

    NO_COLOR is honoured whatever its value, per the convention; FORCE_COLOR
    overrides the terminal check but not the reader's refusal, because one of
    those is a preference and the other is an environment.
    """

    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - a stream with no opinion is not a terminal
        return False


def _truecolor() -> bool:
    return os.environ.get("COLORTERM", "").lower() in {"truecolor", "24bit"}


@dataclass(frozen=True)
class Style:
    """Five roles. Disabled, every one of them is the identity function.

    That is the property worth having: with colour off the output is not
    similar to the uncoloured output, it is the same bytes, so nothing that
    reads this tour has to know the feature exists.
    """

    enabled: bool = False
    rich: bool = False

    @classmethod
    def detect(cls, mode: str = "auto", stream: object | None = None) -> "Style":
        stream = sys.stdout if stream is None else stream
        if mode == "never":
            return cls(enabled=False)
        if mode == "always":
            return cls(enabled=True, rich=_truecolor())
        return cls(enabled=_supported(stream), rich=_truecolor())

    def _paint(self, text: str, rgb: tuple[int, int, int], bold: bool = False) -> str:
        if not self.enabled or not text:
            return text
        weight = "1;" if bold else ""
        if self.rich:
            code = f"{weight}38;2;{rgb[0]};{rgb[1]};{rgb[2]}"
        else:
            code = f"{weight}{BASIC[rgb]}"
        return f"\033[{code}m{text}\033[0m"

    def heading(self, text: str) -> str:
        return self._paint(text, STEEL, bold=True)

    def quiet(self, text: str) -> str:
        return self._paint(text, STEEL_DIM)

    def admitted(self, text: str) -> str:
        return self._paint(text, OK, bold=True)

    def refused(self, text: str) -> str:
        return self._paint(text, NO, bold=True)

    def warning(self, text: str) -> str:
        return self._paint(text, WARN, bold=True)

    def verdict(self, ok: bool, text: str) -> str:
        """For the two lines a viewer looks at before reading anything else."""

        return self.admitted(text) if ok else self.refused(text)

    def badge(self, text: str, rgb: tuple[int, int, int]) -> str:
        """A filled block rather than a coloured word.

        The verdict is the one thing on screen a viewer should find without
        reading, and a label field is exactly eight columns wide whether it is
        painted or not - so this fills that field and takes none of anyone
        else's space.
        """

        if not self.enabled or not text:
            return text
        ink = "38;2;16;24;32" if self.rich else "30"
        ground = (
            f"48;2;{rgb[0]};{rgb[1]};{rgb[2]}" if self.rich else f"{BASIC[rgb] + 10}"
        )
        return f"\033[1;{ink};{ground}m{text}\033[0m"

    def verdict_badge(self, ok: bool, text: str) -> str:
        return self.badge(text, OK if ok else NO)


OFF = Style(enabled=False)
