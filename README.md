# witness

**A DFIR agent that can only report what it can prove a tool said.**

[![CI](https://github.com/vinayvobbili/witness/actions/workflows/ci.yml/badge.svg)](https://github.com/vinayvobbili/witness/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/witness-cli)](https://pypi.org/project/witness-cli/)
[![Python](https://img.shields.io/pypi/pyversions/witness-cli)](https://pypi.org/project/witness-cli/)
[![License](https://img.shields.io/pypi/l/witness-cli)](https://github.com/vinayvobbili/witness/blob/main/LICENSE)

An agent's claim goes in with the tool records it cites. witness re-reads each cited field, admits
the claim only if every value matches, and otherwise refuses it with the exact reason. One command,
`python demo.py`, shows it on captured Volatility output: seven claims, two admitted, five refused.

![witness: seven claims checked against captured Volatility output, two admitted and five refused with the reason](https://raw.githubusercontent.com/vinayvobbili/witness/main/docs/demo.gif)

With sound (1¾ minutes): [docs/demo.mp4](docs/demo.mp4)

Autonomous forensics agents do not usually fail by missing evil. They fail by inventing it —
a transposed octet in an IP, a mis-read defanged domain, a benign LOLBin called malware, a
kernel driver called a rootkit when it was the acquisition tool.

The common defence is a second language model that argues with the first. A second model can
be talked out of a correct refutation. `witness` uses a different kind of oracle: **a finding
is admitted only if a deterministic check confirms that the cited tool output really says what
the claim says it says.**

## Run it

```bash
git clone https://github.com/vinayvobbili/witness && cd witness
python demo.py
```

That is the whole setup. No install, no API key, no 3 GB memory image, no network, and no
dependency outside the standard library — the fixtures are real Volatility 3 output captured
from two SANS SRL-2018 hosts, one clean and one compromised.

Into a terminal it colours the labels and the verdicts, and into a pipe it does not. Values are
never painted, so a hash or a PID reads the same either way, and `--color never` returns the
plain output byte for byte.

Three seconds later you will have watched seven claims go through the gate: the intrusion's real
kill chain admitted with every link bound to a field, a fabricated C2 refused because no record
contains it, a genuine citation with one digit wrong refused, a perfectly cited claim refused
because the conclusion drawn from it is wrong, a claim held open because nobody ran the tool
that would settle it — and the C2 that only exists once you decode for it. Then the case is
thrown away and rebuilt from the captures alone, to the same hash.

Each of those seven declares what it expects **before** the gate is asked, and the run exits
non-zero if any of them lands the other way. A demo that narrates whatever happened goes on
looking impressive after the thing underneath it has broken.

### Or install it, to point at your own evidence

```bash
pip install witness-cli    # the module and the command are both `witness`
```

The two are for different things and it is worth being straight about which. The wheel carries
the library and the CLI, so `pip install` is what you want when the evidence is yours — your
Volatility output, your API responses, your exports. The clone carries the fixtures, the
adversarial catalogue and `demo.py`, so it is what you want when the question is whether any of
this works. Installing does not get you the proof, and it is not supposed to.

The distribution is `witness-cli` because `witness` on PyPI has belonged since 2017 to an
unrelated project. Nothing else changes: you `import witness` and you run `witness`.

### Where to look, by how long you have

- **Three seconds, then two minutes reading it** — `python demo.py`. The argument end to end, on
  real evidence.
- **Ten** — the demo, then [`docs/ACCURACY.md`](docs/ACCURACY.md) for what being careful costs.
- **Half an hour** — `python scripts/adversarial.py` for what a hostile string in a memory image
  can make this say, then `python scripts/prove.py` for the long-form case.
- **Reading rather than running** — `src/witness/verify.py` is the gate and
  `src/witness/falsify.py` is the falsification matrix. Both are short enough to read in one
  sitting, and they are where the argument actually lives.
- **Watching rather than reading** — [`docs/DEMO.md`](docs/DEMO.md) is the shot list for the
  three-minute recording, beat by beat, including `--pace` for pausing between them.

## How the gate works

Every claim carries bindings — *record R, field F, has value V*. Before anything is written,
a pure-Python verifier re-reads R from the store and compares F to V.

```
evidence -> read-only collector -> parsed, typed, hashed records -> append-only store
                                                                          |
agent queries records (never raw dumps) --------------------------------- +
   |
   +-- submit_finding(claim, bindings)
              |
              v
        verifier (no LLM)
          record exists?  field exists?  value matches exactly?
          originating tool call in the chain?  chain intact?
              |
        accept -> ledger      reject -> error, nothing written
```

There is no flag that writes an unverified finding anyway. That is the whole point.

The nearest published approach requires a finding to cite a real tool-call ID. That check
passes for an agent that cites a genuine `psscan` run and then mis-states what row 12 said.
`witness` compares the field value, so it does not.

## Driving it by hand

The tour above is one command because a stranger should not have to assemble the argument.
Underneath it is a CLI, and every step it takes is a step you can take yourself:

```bash
pip install -e .
witness ingest --tool psscan  --input fixtures/wkstn05/psscan.txt  --host base-wkstn-05
witness ingest --tool netscan --input fixtures/wkstn05/netscan.txt --host base-wkstn-05
witness ingest --tool strings --input fixtures/wkstn05/strings.txt --host base-wkstn-05
witness decode --host base-wkstn-05
witness indicators --extract --host base-wkstn-05
witness fields                                   # what kinds this store holds
witness fields --kind process                    # and what those records carry
witness records --kind process --where pid=3720
witness submit --type process_present --claim "PID 3720 is rundll32.exe" \
    --bind RECORD_ID:image_file_name=rundll32.exe --subject pid=3720
witness report --issue
```

`witness demo` runs the same tour as `python demo.py` once the package is installed, and
`scripts/prove.py` is the long-form version: thirteen claims across two hosts, each verdict
printed binding by binding and check by check, then the report and the replay.

`witness fields` is the one worth knowing about. A binding names a field, and anything writing
bindings — a person or an agent — will otherwise guess a name that reads well, `threat_level`
or `verdict` or `malicious`, and be refused. Being refused is the correct outcome and a wasted
turn. The listing is counted from the records rather than declared anywhere, because there is
no schema: a record holds whatever the tool emitted. Four of the eleven fields on a `psscan`
record, verbatim:

```
process  57 record(s) from 1 tool call(s)
  exit_time            57/57  null|text  '2018-08-30 05:14:50.000000 UTC', None, +3 more
  image_file_name      57/57  text       'FireSvc.exe', 'FireTray.exe', 'GROOVE.EXE', 'HipMgmt.exe', +31 more
  session_id           57/57  int        0, 5
  wow64                57/57  bool       False, True
```

Presence is a fraction because records of one kind need not agree. A flattened response has
`indicators.1` only where there were two indicators, and a field on 2 of 3 records is the trap
in every ragged export — it is in the listing, so it looks like part of the shape. The examples
lead with one value of each type, so a column that advertises `null` also shows one.

The listing is a map, not evidence. A field appearing here proves some record carried it, not
that the record a claim is about does — the gate still re-reads that record, which is what lets
this be convenient without being load-bearing.

## It was never only about memory dumps

The gate is a field comparison against a stored record. It has never known that the records
came from Volatility. That is a general claim, and until now the only ways into the store were
a Volatility table and a `strings` dump, which made it look like a memory-forensics trick.

`--tool response` takes JSON from whatever answered a question — a reputation service, an EDR
query, a ticketing API — and lands it on exactly the same terms:

```bash
witness ingest --tool response --source reputation_lookup \
    --records-at engines --kind engine_verdict \
    --evidence-path "GET /domains/example-c2.invalid" \
    --input fixtures/synthetic/reputation_lookup.json
witness records --kind engine_verdict
witness submit --type observation \
    --claim "One engine categorised example-c2.invalid as phishing." \
    --bind RECORD_ID:engine=charlie --bind RECORD_ID:category=phishing
```

Nesting is the only real difficulty. A binding names one field on one record, so a value three
levels down needs a name: every leaf is flattened to its dotted path, list elements by index,
and the same path language picks which part of a response holds the records. Without
`--records-at` the whole document is one record, and a claim binds to
`data.attributes.last_analysis_stats.malicious` the way it would bind to `pid`.

Two rules there are deliberate. **Nothing is truncated** — the store keeps the hash of the raw
response rather than its text, so these records are the only copy of what it said, and a
shortened value would let a claim bind to a prefix of evidence that exists in full nowhere.
And **an empty container is a leaf, not an absence** — `{"tags": []}` records `tags` as `[]`,
because "the service reported no tags" and "the service was never asked" are different
refusals and should not collapse into one.

What it does not do is form an opinion. Whether 12 of 70 engines flagging a file means the file
is malicious is not a question this collector answers. Whether the response really said 12 is.

Not everything answers in JSON. Most EDR and SIEM exports are a header row and some delimited
lines, so `--format` also takes `csv`, `tsv` and `jsonl`:

```bash
witness ingest --tool response --source edr_export --format csv --kind detection \
    --input fixtures/synthetic/detections.csv
witness records --kind detection --where detection_id=D-1002
```

The format is **declared, never sniffed**. A delimiter guessed wrong does not fail — it
produces plausible records with the wrong fields, and plausible-and-wrong is the one outcome
this repository exists to prevent. Read as TSV, that CSV is a single column, which is wrong
loudly rather than quietly.

Delimited cells are stored as the text they are. A CSV carries no types to preserve, and
converting at ingest would turn `00417` into `417` and lose an account id to a column that
looked numeric. The gate coerces both sides at comparison time instead, so a claim of `70`
still binds to a cell reading `70` — and a claim of `417` does not bind to one reading `00417`.
That last part was a real hole: until this collector existed every field was typed at ingest,
so nothing in the store was ever a padded identifier, and `coerce` read `007` as `7`. It no
longer does, and the adversarial catalogue has the case.

Anything wrong with a header is fatal, because it is wrong for every row: a duplicate column
name would make a binding ambiguous, and an unnamed column is a field no claim can cite.
Anything wrong with one row costs that row and is reported. A byte-order mark on the first
header cell is stripped — otherwise every binding to `id` fails as *no such field* and nobody
can see why.

This one ships without a real case behind it, unlike the disk collector below, and the
difference is worth stating rather than glossing. A disk collector with no disk evidence would
be a claim about this case's coverage. A response collector claims only that a given document
flattens to given fields and refuses claims that misquote them, and its fixture is exactly the
evidence for that. The fixtures are synthetic and named so they cannot be mistaken otherwise:
`example-c2.invalid` and `host-a.example.invalid` are reserved by RFC 2606, `203.0.113.10` is
TEST-NET-3, and none of them corroborates anything in the case.

## What the gate catches on real evidence

The true kill chain on `base-wkstn-05` — `WmiPrvSE.exe` (2676) to `powershell.exe` (3920) to
`powershell.exe` (1332) to `rundll32.exe` (3720) — is **accepted**, every link bound to a
parsed `psscan` field.

These are **rejected**, and nothing reaches the ledger:

- A transposed parent PID (`1233` for `1332`). The record says otherwise.
- An external C2 at `185.220.101.5`. Plausible, and the kind of thing an agent reaches for —
  but no `netscan` record contains that address, so there is nothing to bind to.
- A real record cited with a wrong value (`PID 2676 is malware.exe`). Provenance is genuine;
  the claim still fails.
- A conclusion with no bindings at all (`this host is compromised`).
- `subject_srv.exe` where the tool emitted `subject_srv.ex`. Volatility truncates
  `ImageFileName` at the 14 bytes the kernel structure holds, so the fuller name is an
  inference, not evidence. The rejection says so, and the agent can rebind.

One case is accepted with a note rather than rejected: `Sysmon64.exe` against a record reading
`sysmon64.exe`. Same Windows object, so the finding stands, and the ledger records that the
value was case-normalised instead of quietly smoothing it over.

## The second gate: what would prove this wrong?

Quoting the evidence perfectly and drawing the wrong conclusion from it is the harder failure,
and gate 1 does nothing about it. So every finding type declares, up front, the evidence that
would refute it — as a query or a predicate, never as a second opinion from a model.

Three outcomes, and the third is the one that matters:

- **corroborated** — the refuting evidence was looked for and is not there.
- **refuted** — the tool ran and shows the opposite. The claim dies and the attempt is logged.
- **unavailable** — the tool that would settle it was never run. **This is not a pass.** A claim
  nobody tried to disprove is not admitted; the agent is told which tool to run first.

On `base-wkstn-01`, the clean baseline host, both of these are rejected — and both are calls the
graded find-evil run had to make by hand:

- *svchost.exe (2332) contains injected code.* `windows.malfind` ran and returned zero rows for
  that PID. **Refuted.**
- *svchost.exe beaconed to external C2 at 172.16.4.10:8080.* Every binding verifies — the
  connection is real and the record says exactly this. `172.16.4.10` is RFC1918, so it is proxy
  egress, not command and control. **Refuted.** This is the case that gate 1 alone waves through.

The same injection claim against `base-wkstn-05`, where malfind was never run, comes back
**unavailable** rather than refuted. Checks are host-scoped, so one image never corroborates a
finding about another.

Two more properties fall out of this:

- **Retroactive.** `witness revalidate` re-runs every check over the ledger and retracts findings
  that no longer survive, so one admitted before the refuting tool landed does not stay admitted.
  Retraction is an append-only correction — the original finding is never deleted.
- **The subject must be grounded.** A finding declares what it is about (`pid=2332`), and that
  value must be one the bindings actually proved. Otherwise an agent could cite records for one
  process and quietly run the checks against another.

`witness types` prints every finding type with the rationale for each check, so the matrix is
readable rather than buried in code.

## Decode rather than describe

`FromBase64String("H4sIAAAA...")` in a carved command line is where an agent's
confidence usually outruns its evidence. "A gzipped PowerShell stager, probably
Empire, beaconing to some C2" is three guesses about bytes that simply decode.

So `witness decode` unwraps instead of characterising. It reads records already in
the store, undoes base64 and gzip in the standard library, recurses into whatever
that reveals, and writes the result as new records — each traceable back through
`derived_from` to the capture it came from. It names no framework and calls
nothing malicious. It unwraps layers and stops.

On `base-wkstn-05` the carve holds the same command line seven times at seven
truncation lengths, which decodes to **one** payload rather than seven: the shorter
captures stay in the store marked as prefixes of the longer one. That payload is
gzip, and truncated, and says so. Inside it is a second base64 blob — 519 bytes of
x86 that never was text — and inside that is a hostname.

## The domain stack: fifteen candidates, one finding

`witness indicators --extract` pulls domains, URLs, addresses and hashes out of
any record and says where each came from. It assigns no score and keeps no
allowlist of reputable sites, both of which would smuggle a judgement in as data.
It records one distinction, because that one is checkable: whether an indicator
was **carved** out of raw image bytes, where every domain in every mail the user
ever opened also lives, or lifted from something that **ran**.

A dotted token is not a hostname just because it is dotted. `IO.MemoryStream` from
a PowerShell command, `Exchange.asmx` from a mail artifact and `base-mail.shiel`
from a carve cut mid-word all match any regex loose enough to match a domain, and
a report listing them as infrastructure has invented three indicators before
anyone has drawn a conclusion. The last label has to be a real TLD; the IANA list
is vendored under `data/` with its version header so extraction stays offline and
identical everywhere. Since that list is a snapshot it can turn away a genuine
name under a newer gTLD, so every suffix it declined is reported in the run output
rather than left to read as a clean sweep.

Three domains from that host, each stopped somewhere different:

- `base-mail.shieldbase.lan` — **refuted.** A `.lan` name cannot resolve on the
  public internet, so it is not external infrastructure, whatever else it is. The
  corporate mail server sits in a memory dump looking exactly as suspicious as a
  C2 does.
- `www.venetodns.trade` — **unproven.** It is genuinely in the image, and it may
  well be the C2. But in this capture it appears in a strings carve with nothing
  tying it to anything that executed, and "found in the image" is not that tie.
  The refusal says which evidence would settle it.
- `aaa.stage.9231829.extranet.wagonwheelgifts.com` — **accepted.** It appears in
  no plaintext anywhere in this evidence. It is only reachable by decoding a
  carved command line twice, and `witness provenance` walks it back through
  `indicators.extract` and `decode.unwrap` to the `strings` run and the image hash.

The graded find-evil run this repo replaces reported `venetodns.trade` as confirmed
C2 and never reported the embedded host at all. It reached that on prose reasoning
about adjacency in a strings dump — reasoning that may be right, and that the
evidence in the capture does not show. Both corrections come from the same rule
applied without an opinion: bind it, or do not claim it.

## The report, and getting the same one back

A DFIR report is where a careful investigation usually stops being checkable. The
findings were bound to evidence in a tool; the report is prose about them, and by the
time a reader has it the two can only be compared by hand.

`witness report` does not narrate. It renders from the ledger, and every value it
prints is re-read from the store as it writes rather than copied from what the finding
claimed when it was admitted. If a record has changed underneath an admitted finding,
the mismatch appears on the line where the value would have gone and the report refuses
to be issued. The rejections are in the body rather than an appendix, and each check
carries the reason it was asked, so a reader sees not just that a claim survived but
what it survived.

There is no clock anywhere in the output. That is what makes the next part work.

```bash
witness --store case.db report --out report.md --issue
witness --store case.db replay --inputs fixtures
witness --store case.db verify-report report.md
```

Nothing in the store is numbered from a clock or a counter: a tool call id comes from
the tool, its arguments and the hash of its output; a record id from the call that
emitted it; a finding id from its type, claim, bindings and subject. So the chain head
is a fingerprint of the case, and `witness replay` turns that from an argument into a
command. It walks the chain of an existing store and performs every step again into an
empty one — re-parsing each capture, re-running each derived analyser, re-submitting
every finding **and every rejection** through both gates — then compares heads.

On the thirteen-claim run above, all three findings, all ten refusals and the issued
report come back byte for byte, from the captures alone. Two properties are worth
pulling out:

- **Captures are matched by hash, never by filename.** Rename every fixture and the
  case still replays; change one character in one of them and it matches nothing and is
  reported missing, rather than quietly replaying as itself under the name it used to
  have.
- **The refusals replay too.** A case that can only reproduce what it accepted has shown
  its conclusions are reproducible while leaving its refusals as assertions — and on
  this case the refusals are the more interesting half.

An issued report is committed to the chain it was rendered from, so `witness
verify-report` answers two questions separately: were these exact bytes issued from this
store, and does what they say still hold. A report can be authentic and stale, and those
should not read alike.

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
breakdown in [`docs/ACCURACY.md`](docs/ACCURACY.md) is the honest way to read it. That
document also lists what the percentages cannot see, including the one that matters
most: **`www.venetodns.trade` is this intrusion's real C2 and this tool refuses it**,
because in the exported captures the name is in a raw carve and in nothing that
executed. Right on this evidence, a miss on this case, and said in the report rather
than rounded away.

## Evidence integrity

Read-only is enforced by absence, not by policy. No module in `collectors/` exposes a write,
shell, or execute verb, so there is no path — adversarial prompt or otherwise — that modifies
an image.

The store is append-only and hash-chained. Every entry commits to its predecessor, so editing
any earlier row breaks every hash after it, and `witness verify-chain` recomputes the lot.
Unlike ledgers that chain only the findings, the parsed records and the tool calls are in the
same chain, so evidence cannot be rewritten under a finding that already cites it. A broken
chain blocks every subsequent submission.

The hash walk alone is not enough, because the queryable copy of a record is a different row
from the chain entry that admitted it — and a finding is checked against the queryable copy.
So `verify-chain` also compares the two, which is what turns deleting the rows that
corroborate a finding from "a fuller run came back empty" into what it is. The finding is
still retracted, but for spoliation rather than for a refutation nobody observed.

Analysers that read records rather than files record the record ids they consumed, so a
domain lifted out of a decoded payload stays three tool calls away from the image it came
from instead of collapsing into "the tool said so". `witness provenance RECORD_ID` walks it.

Findings are host-scoped from their evidence, not from their prose. A claim naming a host it
did not bind is refused, and a finding whose bindings straddle two machines is refused as
well — the checks have to run against one host, and which one cannot be a matter of wording.

## Rejections are part of the output

Every claim stopped at either gate is written to the chain with the reason it died, and
`witness rejections` prints them. A report is worth more when you can see what did not make it
in — on the run above, three findings are admitted and ten are stopped, each with a recorded
refutation.

## Status

Slices 1 to 7 of a rebuild: the store, `info` / `psscan` / `netscan` / `malfind` / `strings`
collectors, the payload decoder, the indicator oracle, both gates, the ledger, retraction, the
rejection log, the provenance walk, the report, replay, the adversarial catalogue, the accuracy
corpus, and the guided tour. No runtime dependencies — the only bundled data is the IANA TLD
list, and a test parses every shipped module to keep it that way rather than trusting that
nobody added an import.

The captures that make up the shipped case are declared once, in `casefile.py`, because three
things need the same answer to "what evidence is in here" and a list maintained in three places
drifts.

The indicator engine is in this repo, in one file you can read end to end. The submission this
replaces imported it from a separate package, which meant anyone cloning the repo could not
read the thing the repo was about.

Collectors run in replay mode — they ingest captured output carrying its evidence hash — which
is what makes the demo reproducible without a 3 GB image. Live mode is the same parsers behind a
subprocess call.

Known limits, stated rather than discovered later:

- `malfind`'s trailing `Hexdump` and `Disasm` columns are multi-line in Volatility's default
  renderer. The parser reads the tabular prefix and reports any line it cannot fit rather than
  dropping it silently; ingesting the CSV renderer instead is the proper fix. The empty-result
  fixture is a real capture, the with-hits fixture under `fixtures/synthetic/` is hand-written.
- The vendored TLD list is a snapshot, so a name under a very new gTLD would be declined.
  Declined suffixes are reported on every extraction run for exactly this reason.
- The stage-1 payload on `base-wkstn-05` is a truncated gzip stream, because the carve that
  captured it was cut at a page boundary. What inflated is kept and flagged `truncated`; the
  bytes past the cut are not in this evidence and are not guessed at.
- The chain is recomputed in full on every submission, and now cross-checks the queryable
  tables as well. Correct, and fine at case scale; it will want an incremental check before it
  sees a large timeline.
- Replay reproduces retractions by re-running the revalidation pass rather than by replaying
  each retraction where it sits in the chain. A case whose retractions were interleaved with
  later submissions can therefore replay to a different head — which the run reports as a
  mismatch rather than papering over.
- No check currently in the registry can flip from corroborated to refuted by appending
  evidence, so the retroactive machinery is exercised in the tests against a finding type
  registered there rather than shipped. Testing it against a shipped type would need evidence
  nobody captured.

- Decoding stops at 8 MiB per payload. A genuine payload larger than that is reported
  `capped` rather than silently halved, but it is still not fully read — raise the
  ceiling deliberately rather than discover the cap in a report.
- The homoglyph pass reports domain-shaped tokens it cannot read; it does not resolve
  them. Mapping `trаde` to `trade` is a judgement about intent, and this extractor does
  not make those.
- The accuracy numbers are measured on two hosts, because two is what the SANS set
  exported — not because two is enough. No claim is made about a third.
- There is not one routable foreign address in either host's connection table, so the
  admitting branch of the `external_c2` predicate is exercised by unit tests rather than
  by this case. Refusing 168 internal peers called C2 is a real result about a real
  failure mode; it is not evidence that a true external C2 would be admitted.
- A rejection is identified by its type, claim and reason, so the same claim refused the
  same way twice is one ledger line rather than two. On the accuracy run that turns 564
  refusals into 406 entries. Deliberate — a report should not print one refusal ninety
  times — and stated because a count that quietly deduplicates reads higher than it is.

Not yet built: disk and event-log collectors.
There is a specific reason the first of those is absent rather than stubbed. The SRL-2018 case
does have a disk image with Sysmon and PowerShell Operational logs, and they would corroborate
this host's execution chain — but no export of them exists in the captured evidence set here.
A collector with no evidence behind it is a claim about coverage, and this repo's whole argument
is that those get marked unavailable rather than shipped.

## Tests

```bash
python demo.py                  # the guided tour, no install needed
pip install -e ".[dev]"
pytest                          # 349 tests, 120 adversarial cases, 1,083 accuracy claims
python scripts/prove.py         # both gates on real evidence, then report and replay
python scripts/adversarial.py   # the attack catalogue, family by family
python scripts/accuracy.py      # precision, recall, and the reason each refusal gave
```

The demo is in the suite too, and not only as "it exited zero". The tests check that the
numbers it narrates are the numbers in the store it built, that the catalogue sizes it quotes
are counted from the catalogues rather than typed into a string, that a beat landing the wrong
way fails the run, and that a copy of this repository somewhere else on disk runs it with
nothing installed.

## License

MIT.
