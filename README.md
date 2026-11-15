# witness

**A DFIR agent that can only report what it can prove a tool said.**

[![CI](https://github.com/vinayvobbili/witness/actions/workflows/ci.yml/badge.svg)](https://github.com/vinayvobbili/witness/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/witness-cli)](https://pypi.org/project/witness-cli/)
[![Python](https://img.shields.io/pypi/pyversions/witness-cli)](https://pypi.org/project/witness-cli/)
[![License](https://img.shields.io/pypi/l/witness-cli)](https://github.com/vinayvobbili/witness/blob/main/LICENSE)

<p align="center">
  <a href="https://vinayvobbili.github.io/witness/#demo" title="Watch the 1¾-minute demo">
    <img src="https://raw.githubusercontent.com/vinayvobbili/witness/main/docs/demo-thumb.jpg" alt="Play the demo: seven claims checked against captured Volatility output, two admitted, five refused" width="720">
  </a>
  <br><sub>Watch the 1¾-minute demo (with sound)</sub>
</p>

Forensics agents do not fail by missing evil, they fail by inventing it: a transposed octet, a benign LOLBin called malware. The demo feeds seven claims about real captured Volatility output to the gate. A claim is admitted only if a deterministic check re-reads the cited field and it says what the claim says. No second model argues with it. Two claims are admitted and five are refused, each with the exact reason:

| Claim | Verdict | Why |
|---|---|---|
| WmiPrvSE.exe spawned powershell, which spawned powershell, which spawned rundll32.exe | admitted | all six cited fields re-read and match |
| The host beaconed to external C2 185.220.101.5 | refused | no record anywhere contains that address |
| rundll32.exe (3720) was spawned by PID 1233 | refused | the record is real, but it says the parent is 1332 |
| svchost.exe beaconed to external C2 172.16.4.10:8080 | refused | the citations are right, but 172.16.4.10 is a private address, not a public one |
| rundll32.exe (3720) contains injected code | refused | nobody ran `windows.malfind` on that host, so the claim is held and the missing tool is named |
| The host beaconed to C2 www.venetodns.trade | refused | the name is in the memory strings but in nothing that executed (the intrusion's real C2, and a known miss) |
| The PowerShell stager beacons to `aaa.stage.9231829.extranet.wagonwheelgifts.com` | admitted | found only by decoding the carved command line, in something that ran |

## Quick start

```bash
pip install witness-cli                  # the library and the `witness` command
git clone https://github.com/vinayvobbili/witness && cd witness
python demo.py                           # or `witness demo`; the captured evidence is in the clone
```

No API key, no memory image, no network, nothing outside the standard library.

## How well does it work

On 1,083 claims in 29 error classes over the two SANS SRL-2018 hosts: precision 100% (519 of 519 admitted were supported), recall 100% (519 of 519 supported claims admitted), reason 100% (564 of 564 refusals named the actual defect). 1,083 is classes times records, not 1,083 independent experiments. See [docs/ACCURACY.md](https://github.com/vinayvobbili/witness/blob/main/docs/ACCURACY.md).

## Tested hard

`python scripts/adversarial.py` runs 120 attacks in nine families, each family one invariant: instructions planted in the image, citations to records that never existed, almost-right values, hostile paths, decoder abuse, edits to the store, and payloads that forge the report. Writing them found seven defects in witness itself (a 194 KB carved string that inflated to 200 MB, a newline that forged a Findings section), all fixed. See [docs/decisions.md](https://github.com/vinayvobbili/witness/blob/main/docs/decisions.md).

## Plugging in

The gate is a small Python API: cite a record, a field and a value, and get a verdict with the reason. Run from a clone, where the fixtures are:

```python
from pathlib import Path
from witness import Binding, Store, submit_finding
from witness.casefile import load

store = Store("case.db")
load(store, Path("fixtures"))                      # captured Volatility output, hashed on ingest
rec = store.query_records(kind="process", host="base-wkstn-05", where={"pid": 3720})[0]["record_id"]

for ppid in (1332, 1233):                          # the true parent, then a wrong one
    verdict, finding_id = submit_finding(
        store, finding_type="suspicious_process_chain",
        claim=f"rundll32.exe (3720) was spawned by PID {ppid}.",
        bindings=[Binding(rec, "pid", 3720), Binding(rec, "ppid", ppid)],
        subject={"pid": 3720})
    print("admitted" if verdict.accepted else f"refused: {verdict.refutation}", finding_id)
```

```
admitted e6fcca3a2a44
refused: 04a43c8f1153#0017.ppid: record says 1332, claim asserts 1233 None
```

For your own evidence, `witness ingest` loads Volatility tables, `strings` dumps or any JSON API response (`--tool response`), and `witness submit` does the same from the command line.

## Scope and known limits

- Measured on memory artifacts only, from two hosts (one clean, one compromised). No disk, event-log or registry collectors yet, and nothing is claimed about a third host.
- Known miss: `www.venetodns.trade` is this intrusion's real C2 and witness refuses it, because the exported captures hold it only in a raw string carve.
- Neither host's connection table has a routable foreign address, so "admit a true external C2" is covered by unit tests, not by this case.
- The hash chain is re-verified on every submission, so cost grows with the square of the case: a thousand claims takes about thirty seconds.

## Read more

- [Using witness](https://github.com/vinayvobbili/witness/blob/main/docs/usage.md): run it, install it, drive it by hand, the tests
- [How it works](https://github.com/vinayvobbili/witness/blob/main/docs/how-it-works.md): the gate, the second gate, decoding, the report
- [Decisions and what failed](https://github.com/vinayvobbili/witness/blob/main/docs/decisions.md): what was tried against it and what accuracy costs
- [Design and status](https://github.com/vinayvobbili/witness/blob/main/docs/design.md): scope, evidence integrity, what is built
- [Accuracy](https://github.com/vinayvobbili/witness/blob/main/docs/ACCURACY.md) (the full per-class results) and the [demo shot list](https://github.com/vinayvobbili/witness/blob/main/docs/DEMO.md)

MIT licensed.
