"""The demo, tested as a claim about the repository rather than as a script.

`python demo.py` is the first thing anyone runs, which makes it the first thing
that can lie. Three properties are worth holding:

- it agrees with the store it built, rather than printing numbers from a script;
- it fails when the gate misbehaves, instead of narrating whatever happened;
- it runs from a clone with nothing installed, which is what "no dependencies"
  means when someone actually checks.
"""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from witness import casefile, demo
from witness.store import Store

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


@pytest.fixture(scope="module")
def toured(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("demo")
    lines: list[str] = []
    tour = demo.run(
        FIXTURES,
        store_path=workdir / "case.db",
        root=ROOT,
        out=lines.append,
    )
    return tour, "\n".join(lines), workdir


# ------------------------------------------------------------------ it works


def test_the_tour_runs_clean(toured):
    tour, _, _ = toured
    assert tour.ok
    assert not tour.off_script


def test_every_beat_landed_where_the_script_said_it_would(toured):
    tour, _, _ = toured
    assert tour.results, "a tour with no beats passes every assertion below for free"
    off = [(r.beat.title, r.beat.expect, r.admitted) for r in tour.results if not r.as_scripted]
    assert not off


def test_both_outcomes_are_demonstrated(toured):
    """A tour that only shows refusals is an advertisement for an off switch."""
    tour, _, _ = toured
    assert any(r.admitted for r in tour.results)
    assert any(not r.admitted for r in tour.results)


def test_the_case_replays_to_the_same_head(toured):
    tour, _, _ = toured
    assert tour.replay_ok
    assert tour.replayed_head == tour.head


# ------------------------------------ the narration agrees with what it built


def test_the_numbers_printed_are_the_numbers_in_the_store(toured):
    """Read back from the store on disk, not from the object that printed them."""
    tour, text, workdir = toured
    store = Store(workdir / "case.db")

    assert tour.records == len(store.query_records())
    assert tour.findings == len(store.list_findings())
    assert tour.rejections == len(store.list_rejections())
    assert tour.chain_entries == len(store.chain_entries())
    assert tour.head == store.head()

    admitted = sum(1 for r in tour.results if r.admitted)
    assert tour.findings == admitted
    assert f"{tour.records} records   {tour.findings} findings" in text
    assert tour.head in text


def test_the_evidence_it_narrates_is_the_evidence_it_loaded(toured):
    _, text, _ = toured
    for capture in casefile.CAPTURES:
        assert f"{capture.host}  {capture.tool}" in text


def test_the_catalogue_sizes_are_read_from_the_catalogues(toured):
    """The two suites it points at are counted, never quoted.

    Printing "119 attacks" from a literal is how a README ends up describing a
    suite that has since grown, shrunk, or stopped running.
    """
    _, text, _ = toured
    sizes = demo.catalogue_sizes(ROOT)
    assert sizes is not None
    import adversarial
    import corpus

    assert sizes["attacks"] == sum(len(f.attacks) for f in adversarial.families())
    assert sizes["families"] == len(adversarial.families())
    assert sizes["classes"] == len(corpus.CLASSES)
    assert f"{sizes['attacks']} crafted attacks" in text
    assert "catalogue sizes, not results" in text


def test_a_missing_catalogue_is_reported_as_absent_rather_than_guessed(tmp_path):
    assert demo.catalogue_sizes(tmp_path) is None


# ---------------------------------------------- the demo has to be able to fail


def test_a_beat_that_lands_the_wrong_way_fails_the_run(tmp_path, monkeypatch):
    """The property that makes the tour worth running unattended.

    Take the beat that is refused because nobody ran malfind, and relabel it as
    one the gate is expected to admit. Nothing about the tool changes; only the
    script's expectation does. The run has to come back not-ok and name the beat.
    """
    real_script = demo.script

    def mislabelled(store):
        beats = real_script(store)
        gap = next(b for b in beats if b.finding_type == "process_injection")
        patched = [b for b in beats if b is not gap]
        patched.append(
            demo.Beat(
                title=gap.title,
                why=gap.why,
                expect=demo.ADMIT,
                finding_type=gap.finding_type,
                claim=gap.claim,
                bindings=gap.bindings,
                subject=gap.subject,
            )
        )
        return patched

    monkeypatch.setattr(demo, "script", mislabelled)
    tour = demo.run(FIXTURES, store_path=tmp_path / "case.db", root=ROOT, out=lambda _: None)

    assert not tour.ok
    assert [r.beat.expect for r in tour.off_script] == [demo.ADMIT]


# ------------------------------------------------- what "no dependencies" means


def _top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_nothing_shipped_imports_anything_but_the_standard_library():
    """The install instruction is `pip install -e .` and nothing else.

    A single stray third-party import turns that into a lie for someone on a
    plane, so it is checked rather than remembered. Test-only helpers are
    exempt - pytest is a dev dependency and is declared as one.
    """
    shipped = sorted((ROOT / "src").rglob("*.py")) + [ROOT / "demo.py"]
    shipped += sorted((ROOT / "scripts").glob("*.py"))
    local = {"witness", "adversarial", "corpus"}

    offenders: dict[str, set[str]] = {}
    for path in shipped:
        extra = _top_level_imports(path) - sys.stdlib_module_names - local
        if extra:
            offenders[str(path.relative_to(ROOT))] = extra
    assert not offenders, offenders


def test_the_version_lives_in_exactly_one_place():
    """pyproject reads the version out of the package rather than restating it.

    A version in two files is a fact maintained in two places, which is the
    thing this whole repository is about not doing.
    """
    import witness

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in pyproject
    assert 'path = "src/witness/__init__.py"' in pyproject
    assert witness.__version__.count(".") == 2


def test_the_demo_runs_from_a_bare_copy_with_nothing_installed(tmp_path):
    """Copy the repository somewhere else, run one command, expect zero.

    This is the clone-and-run path, and it is the one nobody tests because it
    works on the machine that wrote it. Running from a copy also proves the
    bootstrap in demo.py resolves `witness` next to itself rather than leaning
    on whatever is already installed here.
    """
    clone = tmp_path / "clone"
    shutil.copytree(
        ROOT,
        clone,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "__pycache__", "*.pyc", ".pytest_cache", "*.egg-info"
        ),
    )

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-I", "demo.py"],
        cwd=clone,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]
    assert "chain intact: True" in proc.stdout
    assert "OFF SCRIPT" not in proc.stdout


def test_the_installed_entry_point_runs_the_same_tour(capsys):
    from witness.cli import main

    assert main(["demo", "--fixtures", str(FIXTURES)]) == 0
    assert "WHAT THIS RUN LEFT BEHIND" in capsys.readouterr().out


def test_the_entry_point_says_so_when_the_evidence_is_not_where_it_looked(tmp_path, capsys, monkeypatch):
    from witness.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["demo", "--fixtures", str(tmp_path / "nowhere")]) == 1
    assert "cannot find the fixtures" in capsys.readouterr().out
