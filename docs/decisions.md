# Decisions and what failed

What was decided, what failed, what has been thrown at the gate, and what accuracy costs. Back to the [README](../README.md).

## Decisions and what failed

- **No second model as the checker.** A model that argues with the first one can be talked out
  of a correct refutation, so the gate is plain Python that re-reads the cited field and compares
  the value.
- **Compare the value, not just the tool-call ID.** Requiring a real call ID passes an agent that
  cites a genuine `psscan` run and then mis-states row 12. Checking the field value does not.
- **The accuracy run found refusals that were right for the wrong reason.** Fifty-seven claims were
  refused correctly but logged against a subject their bindings never proved. `Verdict.refutation`
  now puts a binding that does not verify first, then how the finding is put together, then the
  checks.
- **The attack catalogue found seven defects in witness itself.** One was a 194 KB carved string
  that inflated to 200 MB and used 1.7 GB of memory. All seven were fixed; decoding now stops at a
  byte ceiling and says so when it hits it.
- **Known miss: the real C2 is refused.** `www.venetodns.trade` is this intrusion's C2, but in the
  exported captures it appears only in a raw carve, so the gate declines it. The report says so
  rather than rounding it away.
- **Known limit: two hosts, and no foreign address.** The accuracy numbers come from two hosts,
  and neither connection table has a routable foreign address, so the admitting branch of
  `external_c2` is covered by unit tests, not by this case.


## What has been tried against it

A memory image is not trusted input. Everything in it was writable by whoever was on
the box, and a good deal of it was written by the intruder on purpose. So the
interesting question about a forensics agent is not whether it works on honest
evidence — it is what a crafted string in the dump can make it say.

```bash
python scripts/adversarial.py
```

120 cases across nine families, each family stating one invariant and attacking it
from as many angles as the surface has: text in the image that instructs the reader,
bindings citing records that were never there, values that are almost the value,
subjects the bindings never proved, hostile paths, decoder abuse, direct edits to the
store, and payloads shaped to forge the report or repaint a terminal. The catalogue is
data, so `pytest` and the script run exactly the same cases and adding an attack is
adding a line.

Writing it found seven defects, all fixed rather than documented:

- **A gzip bomb in a carved string.** 194 KB of base64 in a `CommandLine=` string
  inflated to 200 MB — 1.7 GB of resident memory, half a minute of CPU, and a 200 MB
  row written into the store, from bytes an attacker chose to leave in the image.
  Decoding now stops at a byte ceiling, and a payload that hit it says so rather than
  looking complete.
- **A newline in an evidence path forged a Findings section.** The report is markdown
  built out of strings an attacker controls, so a line break in any of them invented
  headings and showed findings that were never admitted. That is this project's own
  failure mode appearing on the way out instead of on the way in, and it does not get
  a pass for that. Untrusted text is now rendered as one inert line.
- **The chain could be cut.** Delete the last entries along with the rows they
  committed and what remains verifies perfectly — a hash chain has no way to know how
  long it used to be. An issued report is the anchor that closes it: it names a state,
  and `verify-report` now says so when the chain no longer contains that state.
- **`verify-chain` raised on a mangled payload** instead of reporting it. An integrity
  check that dies on damaged input is unavailable exactly when it is needed.
- **A homoglyph domain was dropped in silence.** `www.venetodns.trаde` with a Cyrillic
  а matches no ASCII pattern, so it was passed over without a word. Reporting 47
  indicators while quietly ignoring one is worse than admitting one cannot be read;
  these are now counted and surfaced, though deliberately not resolved to what they
  imitate.
- **`３７２０` in fullwidth digits compared equal to PID 3720**, because `\d` matches
  every decimal digit in Unicode. A homoglyph integer is not different in kind from a
  homoglyph domain.
- **A claimed `1` bound to a boolean field**, because Python says `True == 1`.

Two tolerances survived the pass and are deliberate: a case-only difference is the
same Windows object and is admitted with a note in the ledger, and surrounding
whitespace is stripped. Everything else compares exactly — a truncated name, a
zero-width space, a fullwidth period, a Cyrillic е, a substring, a superstring and a
PID off by an octet are all refused.

## How accurate is it, and what does that cost?

```bash
python scripts/accuracy.py
```

An accuracy report with no cost column is an advertisement. A tool that refuses
everything has perfect precision, so precision on its own is free; the number that
has to be published next to it is how much true work it threw away getting there.

The run puts 1,083 claims over both hosts through the real submission path. 519 the
evidence supports, 564 it does not, in 29 classes of the way analysis actually goes
wrong — a transposed PID, a name read one character short, the parent's PID asserted
as the process's own, an RFC1918 peer called external C2, an injection claim on the
host where nobody ran `malfind`.

- **precision 100%** — of 519 admitted findings, 519 were supported
- **recall 100%** — of 519 supported claims, 519 were admitted
- **reason 100%** — of 564 refusals, 564 named the actual defect

The third line is the one that separates accuracy from luck, and it is the one that
found a defect. Fifty-seven claims were being refused correctly and logged for the
wrong reason: their bindings verified, so the checks ran against a subject none of
those bindings proved and truthfully reported that no process exists with that PID.
True, and about the wrong process. `Verdict.refutation` now orders cause before
consequence — a binding that does not verify, then anything wrong with how the
finding is put together, then the checks.

Two things keep the number from grading its own homework. Every claimed value is read
off the captured tool output by a separate reader, never asked of the record it will be
checked against. And the census classes line each raw row up with the record it became
by position, so a row the collector dropped puts every later pair out of step and the
run fails loudly rather than measuring one case fewer and still reporting a clean sweep.

1,083 is classes times records, not 1,083 independent experiments — the per-class
breakdown in [`docs/ACCURACY.md`](ACCURACY.md) is the honest way to read it. That
document also lists what the percentages cannot see, including the one that matters
most: **`www.venetodns.trade` is this intrusion's real C2 and this tool refuses it**,
because in the exported captures the name is in a raw carve and in nothing that
executed. Right on this evidence, a miss on this case, and said in the report rather
than rounded away.

