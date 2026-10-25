"""The README's demo video: its slides and narration. Writes slides/*.html and reel.yaml into the output
folder; then slidecast (https://pypi.org/project/slidecast/) renders the video:

    python scripts/demo/build.py scripts/demo/out [--music DIR]
    slidecast render scripts/demo/out/reel.yaml -o scripts/demo/out/witness-demo.mp4 --poster

`scripts/demo/make-video` does both and copies the result to docs/demo.mp4.

The terminal scenes are not pasted text: this runs `python demo.py --color never` on the repo's own fixtures
and cuts the claims out of what it printed. If the demo stops showing an admitted claim and a refused one,
or the counts the narration states change, the build fails rather than narrating something else.

slidecast is a build tool only, not a dependency: `pip install 'slidecast[mlx]'` (or the `video` extra).
The music bed and stings (music_bed.wav, intro_sting.wav, outro_sting.wav) are read from --music, else from
the output folder; without them the video has the voice only.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "out"

CSS = """
html { zoom: 1.5; }  /* designed at 1280x720, rendered at 1920x1080 */
* { box-sizing: border-box; margin: 0; padding: 0; }
body { width: 1280px; height: 720px; overflow: hidden; color: #eaf3f8;
  font-family: -apple-system, "SF Pro Display", "Helvetica Neue", Arial, sans-serif;
  background: radial-gradient(1100px 650px at 88% -10%, #1d5a73 0%, transparent 60%),
              radial-gradient(900px 600px at -10% 112%, #0f6b4a 0%, transparent 55%), #0a1218; }
.brand { position: absolute; top: 26px; right: 40px; font-weight: 700; font-size: 22px; letter-spacing: -.01em;
  opacity: .9; }
.brand b { color: #7fb3c9; }
header { position: absolute; top: 24px; left: 40px; right: 220px; }
.step { display: inline-flex; align-items: center; gap: 10px; font-size: 15px; font-weight: 700;
  letter-spacing: .08em; text-transform: uppercase; color: #7fb3c9; }
.step i { font-style: normal; width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center;
  background: linear-gradient(135deg, #3fbf7f, #2a8fb0); color: #04120c; letter-spacing: 0; font-size: 14px; }
h1 { font-size: 38px; line-height: 1.1; letter-spacing: -.02em; margin-top: 8px; }
.sub { font-size: 19px; color: #b6cbd6; margin-top: 8px; }
.frame { position: absolute; left: 40px; right: 40px; top: 160px; bottom: 28px; border-radius: 14px;
  overflow: hidden; background: #0d171e; box-shadow: 0 24px 60px rgba(0,0,0,.5), 0 0 0 1px rgba(127,179,201,.22); }
.bar { height: 30px; background: #1a2a34; display: flex; align-items: center; gap: 7px; padding: 0 12px; }
.bar span { width: 11px; height: 11px; border-radius: 50%; background: #ff5f57; }
.bar span:nth-child(2) { background: #febc2e; } .bar span:nth-child(3) { background: #28c840; }
.bar em { margin-left: 14px; font-style: normal; font-size: 12px; color: #8fa9b6; }
.term { position: absolute; top: 30px; left: 0; right: 0; bottom: 0; color: #dbe8ee;
  font: 17px/1.5 "SF Mono", Menlo, monospace; padding: 18px 26px; white-space: pre-wrap; }
.term .p { color: #7ee2a8; } .term .c { color: #819aad; }
.term .ok { color: #3fbf7f; font-weight: 700; } .term .no { color: #ff6b81; font-weight: 700; }
.center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center;
  justify-content: center; text-align: center; padding: 0 110px; }
.center h1 { font-size: 72px; }
.center h1 b { background: linear-gradient(90deg, #7fb3c9, #3fbf7f); -webkit-background-clip: text;
  color: transparent; }
.center .sub { font-size: 25px; margin-top: 18px; max-width: 900px; line-height: 1.4; }
.chips { display: flex; flex-wrap: wrap; gap: 12px; justify-content: center; margin-top: 36px; }
.chips span { border: 1px solid rgba(255,107,129,.5); color: #ffc2cc; border-radius: 999px; padding: 9px 20px;
  font-size: 19px; background: rgba(255,107,129,.1); }
.flow { display: flex; align-items: center; gap: 16px; margin-top: 40px; }
.box { border-radius: 14px; padding: 18px 22px; font-size: 20px; line-height: 1.35; min-width: 190px;
  background: rgba(127,179,201,.12); border: 1px solid rgba(127,179,201,.4); }
.box small { display: block; font-size: 14px; color: #9fb8c6; margin-top: 4px; }
.box.ok { background: rgba(63,191,127,.14); border-color: rgba(63,191,127,.55); }
.box.no { background: rgba(255,107,129,.12); border-color: rgba(255,107,129,.5); }
.arrow { font-size: 30px; color: #7fb3c9; }
.cmd { margin-top: 34px; font: 24px "SF Mono", Menlo, monospace; background: rgba(0,0,0,.4);
  border: 1px solid rgba(127,179,201,.3); border-radius: 12px; padding: 16px 28px; color: #7ee2a8;
  text-align: left; line-height: 1.6; }
"""

BRAND = '<div class="brand">wit<b>ness</b></div>'
HIDDEN_BRAND = BRAND.replace('class="brand"', 'class="brand" style="display:none"')

CLAIM_HEAD = re.compile(r"^  \[(\d+)\] ")
RULE = re.compile(r"^=+$")
WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven"}


def page(body: str) -> str:
    return f'<!doctype html><html><head><meta charset="utf-8"><style>{CSS}</style></head><body>{body}</body></html>'


def head(n: int, label: str, title: str, sub: str) -> str:
    return (f'<header><div class="step"><i>{n}</i>{label}</div><h1>{title}</h1>'
            f'<div class="sub">{sub}</div></header>{BRAND}')


def paint(text: str) -> str:
    """Terminal text as HTML: verdicts and labels coloured, values left exactly as the demo printed them."""
    out = []
    for line in html.escape(text).splitlines():
        line = re.sub(r"\bADMITTED\b", '<span class="ok">ADMITTED</span>', line)
        line = re.sub(r"\bREFUSED\b", '<span class="no">REFUSED</span>', line)
        line = re.sub(r"^(\s+)(why|claim|ledger)(\s)", r'\1<span class="c">\2</span>\3', line)
        out.append(line)
    return "\n".join(out)


def term_slide(n, label, title, sub, text, command="python demo.py"):
    body = f'<span class="p">$</span> {html.escape(command)}\n\n{paint(text)}'
    frame = (f'<div class="frame"><div class="bar"><span></span><span></span><span></span><em>Terminal</em></div>'
             f'<div class="term">{body}</div></div>')
    return page(head(n, label, title, sub) + frame)


def capture_demo(root: Path = ROOT) -> str:
    """What `python demo.py` prints on the repo's fixtures, uncoloured. Fails if the demo itself fails."""
    run = subprocess.run([sys.executable, str(root / "demo.py"), "--color", "never"],
                         capture_output=True, text=True, cwd=root, check=False)
    if run.returncode != 0:
        raise SystemExit(f"demo.py exited {run.returncode}:\n{run.stdout}{run.stderr}")
    return run.stdout


def sections(text: str) -> dict[str, list[str]]:
    """The demo's output by section: the title line between a pair of `====` rules -> the lines after it."""
    lines = text.splitlines()
    rules = [i for i, line in enumerate(lines) if RULE.match(line.strip())]
    found: dict[str, list[str]] = {}
    # Rules come in pairs around each section's title and description; the body runs to the next pair.
    for a, b, nxt in zip(rules[0::2], rules[1::2], rules[2::2] + [len(lines)]):
        found[lines[a + 1].strip()] = lines[b + 1:nxt]
    return found


def claims(text: str) -> dict[int, list[str]]:
    """Each numbered claim block of THE GATE section, by number, trailing blank lines dropped."""
    out: dict[int, list[str]] = {}
    current: list[str] | None = None
    for line in sections(text).get("THE GATE", []):
        m = CLAIM_HEAD.match(line)
        if m:
            current = out.setdefault(int(m.group(1)), [])
        if current is not None:
            current.append(line)
    return {n: "\n".join(block).rstrip().splitlines() for n, block in out.items()}


def verdict(block: list[str]) -> str:
    for line in block:
        for word in ("ADMITTED", "REFUSED"):
            if word in line:
                return word
    return ""


def facts(text: str) -> dict:
    """The numbers the narration states, read from the capture. Raises if the demo no longer shows what the
    narration says (seven claims, some admitted and some refused, a replay that matched)."""
    gate = claims(text)
    verdicts = {n: verdict(b) for n, b in gate.items()}
    admitted = sum(v == "ADMITTED" for v in verdicts.values())
    refused = sum(v == "REFUSED" for v in verdicts.values())
    if len(gate) != 7 or admitted + refused != 7 or not admitted or not refused:
        raise SystemExit(f"the demo no longer shows seven claims, admitted and refused: {verdicts}")
    evidence = " ".join(sections(text).get("THE EVIDENCE", []))
    records = re.search(r"(\d+) records across (\d+) hosts", evidence)
    if not records or not re.search(r"^\s*match\s+True\b", text, re.MULTILINE):
        raise SystemExit("the demo's evidence summary or replay match is missing")
    return {"claims": gate, "admitted": admitted, "refused": refused,
            "records": records.group(1), "hosts": int(records.group(2))}


def pick(gate: dict[int, list[str]], wanted: str, first: int = 1) -> list[str]:
    """The first claim block at or after number `first` with the given verdict."""
    for n in sorted(gate):
        if n >= first and verdict(gate[n]) == wanted:
            return gate[n]
    raise SystemExit(f"no {wanted} claim in the demo output")


def slides(text: str) -> list[tuple[str, str, str]]:
    """(file name, html, narration) for each slide, in order, from the demo's captured output."""
    f = facts(text)
    gate = f["claims"]
    parts = sections(text)
    evidence = "\n".join(line for line in parts["THE EVIDENCE"] if line.strip())
    admitted = pick(gate, "ADMITTED")
    refused = pick(gate, "REFUSED", first=3)  # claim 2 is the invented address; the next is the subtler one
    summary = "\n".join(line for line in parts["THE REPORT"][:1])
    replay = "\n".join(line for line in parts["REPLAY"] if line.strip().startswith(("original", "replayed", "match")))
    total, nadmit, nrefuse = WORDS[len(gate)], WORDS[f["admitted"]], WORDS[f["refused"]]
    return [
        ("01-title",
         page(HIDDEN_BRAND + '<div class="center"><h1>wit<b>ness</b></h1>'
              '<div class="sub">A DFIR agent that can only report what it can prove a tool said.</div></div>'),
         "This is witness: a forensics agent that can only report what it can prove a tool said."),
        ("02-problem",
         page(HIDDEN_BRAND + '<div class="center"><div class="step"><i>1</i>The problem</div>'
              '<h1 style="font-size:52px;margin-top:16px">Agents fail by inventing evil.</h1>'
              '<div class="chips"><span>a transposed octet in an IP</span><span>a benign LOLBin called malware</span>'
              '<span>a driver called a rootkit</span></div></div>'),
         ("Autonomous DFIR agents rarely fail by missing evil. They fail by inventing it. A transposed octet in "
          "an IP address. A benign LOLBin called malware. A driver called a rootkit.")),
        ("03-idea",
         page(HIDDEN_BRAND + '<div class="center"><div class="step"><i>2</i>The idea</div>'
              '<h1 style="font-size:46px;margin-top:16px">A finding needs proof, not a second opinion.</h1>'
              '<div class="flow"><div class="box">claim<small>with bindings: record, field, value</small></div>'
              '<div class="arrow">&rarr;</div><div class="box">deterministic check<small>re-reads the record, '
              'compares the field</small></div><div class="arrow">&rarr;</div>'
              '<div class="box ok">admitted</div><div class="arrow" style="font-size:20px">or</div>'
              '<div class="box no">refused, with the reason</div></div></div>'),
         ("The usual defence is a second model that argues with the first. But a model can be talked out of a "
          "correct answer. Witness uses a different kind of check. A finding is admitted only if deterministic "
          "code confirms that the cited tool output really says what the claim says.")),
        ("04-evidence",
         term_slide(3, "The evidence", "Captured tool output, hashed",
                    "No memory image, no key. Just what the tools said.", evidence),
         (f"The demo runs on captured Volatility output from {WORDS.get(f['hosts'], f['hosts'])} hosts: "
          f"{f['records']} records, each carrying the hash of the tool output it was parsed from.")),
        ("05-admitted",
         term_slide(4, "Admitted", "A true claim survives",
                    "Every binding is re-read from the store and matched.", "\n".join(admitted)),
         ("First, a true claim, a chain of processes. Witness re-reads each bound field from the record and "
          "compares it. They all match, so the finding is admitted.")),
        ("06-refused",
         term_slide(5, "Refused", "One wrong digit, and it stops",
                    "The citation is real. The value is not.", "\n".join(refused)),
         ("Now a claim with one digit wrong. The record it cites is real, but the value in it differs from "
          "the value in the claim. Refused, and the reason says exactly why.")),
        ("07-tally",
         term_slide(6, "The tally", f"{total.capitalize()} claims, {nadmit} admitted",
                    "Then the case is rebuilt from the captures alone.", summary + "\n\n" + replay),
         (f"Of {total} claims, {nadmit} were admitted and {nrefuse} were refused: an invented address, a wrong "
          "digit, a wrong conclusion, a tool nobody ran. Then the case is thrown away and rebuilt from the "
          "captures alone, to the same hash.")),
        ("08-run",
         page(HIDDEN_BRAND + '<div class="center"><div class="step"><i>7</i>Try it</div>'
              '<h1 style="font-size:52px;margin-top:16px">Nothing to install.</h1>'
              '<div class="cmd">git clone https://github.com/vinayvobbili/witness<br>cd witness &amp;&amp; '
              'python demo.py</div><div class="sub">No pip, no API key, no network.</div></div>'),
         ("To try it, clone the repository and run python demo.py. Nothing to install, no API key, no "
          "network. It takes about three seconds.")),
    ]


# The music bed and stings (`slidecast compose -o DIR` makes them), and how loud each plays.
AUDIO = {"music": ("music_bed.wav", {"volume": 0.3, "fade_in": 1.0, "fade_out": 3.0, "duck": True, "duck_db": 16}),
         "intro": ("intro_sting.wav", {"volume": 0.75}),
         "outro": ("outro_sting.wav", {"volume": 0.7})}

# Kokoro mangles acronyms and file names; spell them the way they should be said.
PHONETIC = {r"\bDFIR\b": "D F I R", r"\bLOLBin\b": "lol bin", r"\bIP\b": "I P", r"\bAPI\b": "A P I",
            r"demo\.py": "demo dot pie"}


def build_spec(entries: list[dict], out: Path, music: Path | None = None) -> dict:
    """The reel: `entries` are the slides; the music bed and stings come from `music`, else from `out`;
    without them the reel has the voice only."""
    spec = {"width": 1920, "height": 1080, "fps": 25,
            "tts": {"provider": "mlx", "voice": "af_heart",  # Kokoro in-process: pip install 'slidecast[mlx]'
                    "phonetic": PHONETIC}}
    where = (music or out).expanduser().resolve()
    missing = [name for name, _ in AUDIO.values() if not (where / name).is_file()]
    if music and missing:
        raise SystemExit(f"{where} has no {', '.join(missing)}: `slidecast compose -o {where}` makes them")
    if not missing:
        for key, (name, opts) in AUDIO.items():
            spec[key] = {"file": name if where == out else str(where / name), **opts}
    spec.update({"lead_in": 1.8, "loudness": -16, "slides": entries})
    return spec


def build(out: Path, music: Path | None = None, text: str | None = None) -> dict:
    """Write slides/*.html and reel.yaml into `out`. `text` is the demo's output (captured now when omitted).
    Returns the reel's spec."""
    out = out.expanduser().resolve()
    (out / "slides").mkdir(parents=True, exist_ok=True)
    entries = []
    for name, body, narration in slides(capture_demo() if text is None else text):
        (out / "slides" / f"{name}.html").write_text(body, encoding="utf-8")
        entries.append({"html_file": f"slides/{name}.html", "narration": narration, "tail_pad": 1.3})
    entries[0]["tail_pad"] = 1.0
    entries[-1]["tail_pad"] = 1.6
    spec = build_spec(entries, out, music)
    # JSON is YAML, and keeps this script free of a yaml dependency.
    (out / "reel.yaml").write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return spec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", nargs="?", type=Path, default=OUT, help=f"the output folder (default: {OUT})")
    ap.add_argument("--music", type=Path, metavar="DIR",
                    help="the folder holding music_bed.wav, intro_sting.wav and outro_sting.wav")
    args = ap.parse_args(argv)
    spec = build(args.out, args.music)
    print(f"Wrote {len(spec['slides'])} slides and {args.out / 'reel.yaml'}"
          + ("" if "music" in spec else " (no music: voice only)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
