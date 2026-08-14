"""Slice 5: run the attack catalogue, one test per attack.

The cases live in `adversarial.py` as data so that this file and
`scripts/adversarial.py` run exactly the same ones, and so that a new attack is
a new line rather than a new function.
"""

import pytest
from adversarial import Attack, catalogue, families, run

CASES = catalogue()


def _identify(attack: Attack) -> str:
    return f"{attack.family}:{attack.name}"


@pytest.mark.parametrize("attack", CASES, ids=_identify)
def test_attack_is_blocked(attack):
    outcome = run(attack)
    assert outcome.blocked, f"{_identify(attack)} - {outcome.detail}"


def test_the_catalogue_is_the_size_it_claims_to_be():
    """The count is quoted in the README, so it is asserted rather than remembered."""
    assert len(CASES) >= 100
    assert len(CASES) == sum(len(family.attacks) for family in families())
    assert len({(a.family, a.name) for a in CASES}) == len(CASES), "no duplicate cases"


def test_every_family_states_an_invariant():
    for family in families():
        assert family.invariant.endswith("."), family.name
        assert family.attacks, f"{family.name} has no attacks"
