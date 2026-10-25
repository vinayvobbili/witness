"""The README's demo video, tested as its script rather than its pixels.

`scripts/demo/build.py` runs `python demo.py` and cuts the claims out of what it printed. What matters is that
the video can only show what the demo showed: the slides are built from the captured text, and the narration's
counts come from it, so a demo that changes makes the build fail instead of narrating something else. Nothing
here renders anything; slidecast is a build tool and is not imported.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

FAKE = """
============================================================================
  THE EVIDENCE
  captured output
============================================================================
  host-a  windows.info       20 records   sha256(output) 55c7b002cede...

  347 records across 2 hosts - one clean and one compromised.

============================================================================
  THE GATE
  seven claims.
============================================================================

  [1] a true claim
      why      it survives
      claim    proc.exe (1) spawned child.exe (2).
      ADMITTED 2 binding(s) re-read and matched

  [2] an invented address
      claim    The host beaconed to 203.0.113.9.
      REFUSED  nonexistent#0001.foreign_addr: no such record in the store

  [3] one digit wrong
      claim    child.exe (2) was spawned by proc.exe (11).
      REFUSED  x#0017.ppid: record says 1, claim asserts 11

  [4] a wrong conclusion
      claim    c
      REFUSED  peer_is_routable: False

  [5] a tool nobody ran
      claim    c
      REFUSED  malfind_shows_injected_memory: has not been run

  [6] not tied to execution
      claim    c
      REFUSED  domain_appears_in_execution_context: no row

  [7] decoded
      claim    c
      ADMITTED 1 binding(s) re-read and matched

============================================================================
  THE REPORT
  rendered from the ledger
============================================================================
  2 admitted, 5 stopped, 0 retracted, 8 tool call(s) over 2 host(s)
  114 lines.

============================================================================
  REPLAY
  rebuild
============================================================================
  original head  abc
  replayed head  abc
  match          True   (2 findings and 5 refusals came back, in order)
"""


@pytest.fixture(scope="module")
def video():
    spec = importlib.util.spec_from_file_location("demo_video", ROOT / "scripts" / "demo" / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------------ reading the demo's output


def test_sections_are_keyed_by_their_title(video):
    parts = video.sections(FAKE)
    assert list(parts) == ["THE EVIDENCE", "THE GATE", "THE REPORT", "REPLAY"]
    assert any("347 records across 2 hosts" in line for line in parts["THE EVIDENCE"])


def test_claims_are_cut_out_with_their_verdicts(video):
    gate = video.claims(FAKE)
    assert sorted(gate) == [1, 2, 3, 4, 5, 6, 7]
    assert [video.verdict(gate[n]) for n in (1, 2, 7)] == ["ADMITTED", "REFUSED", "ADMITTED"]
    assert gate[1][0].startswith("  [1]")
    assert gate[1][-1].strip().startswith("ADMITTED")


def test_facts_count_what_the_narration_will_say(video):
    f = video.facts(FAKE)
    assert (f["admitted"], f["refused"], f["records"], f["hosts"]) == (2, 5, "347", 2)


@pytest.mark.parametrize("broken", [
    FAKE.replace("  [7] decoded\n      claim    c\n      ADMITTED 1 binding(s) re-read and matched\n", ""),
    FAKE.replace("ADMITTED", "REFUSED"),
    FAKE.replace("match          True", "match          False"),
    FAKE.replace("347 records across 2 hosts", "347 records"),
])
def test_a_demo_that_no_longer_says_it_fails_the_build(video, broken):
    with pytest.raises(SystemExit):
        video.facts(broken)


# ------------------------------------------------------------------ the slides and narration


def test_every_slide_has_a_narration_and_real_captured_text(video):
    entries = video.slides(FAKE)
    names = [name for name, _, _ in entries]
    assert names == sorted(names) and len(set(names)) == len(names)
    assert all(narration.strip() for _, _, narration in entries)
    page = {name: body for name, body, _ in entries}
    assert "one digit wrong" in page["06-refused"] or "ppid" in page["06-refused"]
    assert "record says 1, claim asserts 11" in page["06-refused"]
    assert "invented address" not in page["06-refused"]  # the subtler refusal, not the first
    assert 'class="ok">ADMITTED' in page["05-admitted"]
    assert "347 records across 2 hosts" in page["04-evidence"]
    assert "match" in page["07-tally"]


def test_narration_numbers_come_from_the_capture(video):
    narration = {name: text for name, _, text in video.slides(FAKE)}
    assert "347 records" in narration["04-evidence"]
    assert "Of seven claims, two were admitted and five were refused" in narration["07-tally"]


def test_captured_text_is_escaped(video):
    assert "&lt;b&gt;" in video.paint("<b>")


def test_acronyms_are_spelled_for_kokoro(video):
    assert video.PHONETIC[r"\bDFIR\b"] == "D F I R"
    assert video.PHONETIC[r"\bLOLBin\b"] == "lol bin"
    assert video.PHONETIC[r"\bIP\b"] == "I P"


# ------------------------------------------------------------------ the reel


def test_build_writes_slides_and_a_reel(video, tmp_path):
    spec = video.build(tmp_path, text=FAKE)
    reel = json.loads((tmp_path / "reel.yaml").read_text(encoding="utf-8"))
    assert reel == spec
    assert reel["tts"]["provider"] == "mlx" and reel["tts"]["voice"] == "af_heart"
    assert len(reel["slides"]) == 8
    for entry in reel["slides"]:
        assert (tmp_path / entry["html_file"]).is_file()
    assert "music" not in reel  # no audio files in the folder: the voice only


def test_build_uses_the_music_when_it_is_there(video, tmp_path):
    music = tmp_path / "music"
    music.mkdir()
    for name in ("music_bed.wav", "intro_sting.wav", "outro_sting.wav"):
        (music / name).write_bytes(b"")
    spec = video.build(tmp_path / "out", music=music, text=FAKE)
    assert {"music", "intro", "outro"} <= set(spec)


def test_a_music_folder_missing_files_is_an_error(video, tmp_path):
    with pytest.raises(SystemExit):
        video.build(tmp_path / "out", music=tmp_path, text=FAKE)


def test_the_script_needs_nothing_outside_the_standard_library():
    source = (ROOT / "scripts" / "demo" / "build.py").read_text(encoding="utf-8")
    assert "import slidecast" not in source and "import yaml" not in source
