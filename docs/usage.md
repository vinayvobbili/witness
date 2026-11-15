# Using witness

Run the demo, install the CLI, drive each step by hand, and run the tests. Back to the [README](../README.md).

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
- **Ten** — the demo, then [`docs/ACCURACY.md`](ACCURACY.md) for what being careful costs.
- **Half an hour** — `python scripts/adversarial.py` for what a hostile string in a memory image
  can make this say, then `python scripts/prove.py` for the long-form case.
- **Reading rather than running** — `src/witness/verify.py` is the gate and
  `src/witness/falsify.py` is the falsification matrix. Both are short enough to read in one
  sitting, and they are where the argument actually lives.
- **Watching rather than reading** — [`docs/DEMO.md`](DEMO.md) is the shot list for the
  three-minute recording, beat by beat, including `--pace` for pausing between them.


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

