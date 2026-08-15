"""What the records in a store actually carry, counted rather than declared.

There is no schema here and there was never going to be one. A record holds
whatever the tool emitted, and two records of the same kind need not hold the
same fields: a flattened response has `indicators.1` only when there were two
indicators, and a CSV column can be blank on one row and not another. So this
module does not describe a shape the store promises. It reports the shape the
evidence turned out to have.

That matters more than it sounds. A binding names a field, and an agent that has
to guess a field name will guess one that reads well - `threat_level`, `verdict`,
`malicious` - and be refused. Being refused is the correct outcome and a wasted
turn. Reading the field list first is the difference between an agent that
invents names and one that cannot.

Presence is reported as a fraction for the same reason. A field on 2 of 3 records
is the trap in every ragged export: it is in the listing, so it looks like part of
the shape, and binding to it on the third record fails. Saying `2/3` in the column
where the eye already is costs nothing and removes the surprise.

None of this is evidence. A field appearing here proves some record carried it,
not that the record a claim is about does. The gate still re-reads that record,
which is why a listing can be this convenient without being load-bearing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .report import safe
from .store import Store

# How many distinct values to print before saying how many were left out. Four
# fits a terminal line beside a name and a type, and is enough to see that a
# column is an enum rather than free text. The budget stops one paragraph-length
# value from taking the line; whatever either cap leaves out is counted, so the
# two never disagree about how much was not shown.
SAMPLE = 4
VALUE_WIDTH = 32
VALUES_BUDGET = 60


def type_name(value: Any) -> str:
    """The type as an analyst would say it, not as Python spells it."""
    if value is None:
        return "null"
    if isinstance(value, bool):  # before int: a bool is an int in Python, not here
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "text"
    return type(value).__name__


@dataclass
class Kind:
    kind: str
    records: int
    tool_calls: int


@dataclass
class Field:
    name: str
    present: int
    types: list[str]
    distinct: int
    examples: list[Any]

    @property
    def values(self) -> str:
        """Some of what this field held, and how much was not shown.

        Values are rendered the way the gate renders them in a verdict, so
        `'00417'` and `417` do not read as the same thing here either.
        """
        shown: list[str] = []
        used = 0
        for value in self.examples:
            rendered = safe(repr(value), VALUE_WIDTH)
            if shown and used + len(rendered) > VALUES_BUDGET:
                break
            shown.append(rendered)
            used += len(rendered) + 2
        if self.distinct > len(shown):
            shown.append(f"+{self.distinct - len(shown)} more")
        return ", ".join(shown)


@dataclass
class Shape:
    kind: str
    records: int
    tool_calls: int
    fields: list[Field]


def _examples(distinct: dict[tuple[str, Any], Any]) -> list[Any]:
    """One value of each type first, then fill up in a stable order.

    Nulls sort last under any ordering that puts them next to strings, so a
    column of timestamps with two blanks in it would advertise `null|text` and
    then show four timestamps. The one value that explains the type column is the
    one that falls off the end. Leading with a value per type fixes that, and
    costs nothing on a field that only ever held one type.
    """
    def rendered(item: tuple[tuple[str, Any], Any]) -> str:
        return safe(repr(item[1]), VALUE_WIDTH)

    ordered = sorted(distinct.items(), key=rendered)
    leading: list[tuple[str, Any]] = []
    taken: set[str] = set()
    for key, _ in ordered:
        if key[0] not in taken:
            taken.add(key[0])
            leading.append(key)
    chosen = leading + [key for key, _ in ordered if key not in leading]
    return [distinct[key] for key in chosen[:SAMPLE]]


def kinds(store: Store, host: str | None = None) -> list[Kind]:
    """Every record kind in the store, with how much of each there is."""
    counts: dict[str, int] = {}
    calls: dict[str, set] = {}
    for row in store.query_records(host=host):
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
        calls.setdefault(row["kind"], set()).add(row["tool_call_id"])
    return [Kind(kind, counts[kind], len(calls[kind])) for kind in sorted(counts)]


def describe(store: Store, kind: str, host: str | None = None) -> Shape | None:
    """Count the fields across every record of one kind. None if there are none."""
    rows = store.query_records(kind=kind, host=host)
    if not rows:
        return None

    present: dict[str, int] = {}
    types: dict[str, set[str]] = {}
    # Keyed by (type, value) rather than value, so True and 1 stay two values -
    # the same distinction the gate makes when it refuses a number claimed
    # against a boolean field.
    seen: dict[str, dict[tuple[str, Any], Any]] = {}

    for row in rows:
        for name, value in row["fields"].items():
            present[name] = present.get(name, 0) + 1
            kind_of = type_name(value)
            types.setdefault(name, set()).add(kind_of)
            seen.setdefault(name, {}).setdefault((kind_of, value), value)

    fields = []
    for name in sorted(present):
        fields.append(
            Field(
                name=name,
                present=present[name],
                types=sorted(types[name]),
                distinct=len(seen[name]),
                examples=_examples(seen[name]),
            )
        )

    return Shape(
        kind=kind,
        records=len(rows),
        tool_calls=len({row["tool_call_id"] for row in rows}),
        fields=fields,
    )
