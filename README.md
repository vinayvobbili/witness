# witness

**A DFIR agent that can only report what it can prove a tool said.**

Autonomous forensics agents do not usually fail by missing evil. They fail by inventing it —
a transposed octet in an IP, a mis-read defanged domain, a benign LOLBin called malware, a
kernel driver called a rootkit when it was the acquisition tool.

The common defence is a second language model that argues with the first. A second model can
be talked out of a correct refutation. `witness` uses a different kind of oracle: **a finding
is admitted only if a deterministic check confirms that the cited tool output really says what
the claim says it says.**

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

## Try it in thirty seconds

No API key, no evidence image, no dependencies beyond the standard library. The fixtures are
real Volatility 3 output captured from the SANS `base-wkstn-05` memory image — a genuinely
compromised Windows 7 host from the SRL-2018 case.

```bash
pip install -e .
witness ingest --tool psscan  --input fixtures/wkstn05/psscan.txt  --host base-wkstn-05
witness ingest --tool netscan --input fixtures/wkstn05/netscan.txt --host base-wkstn-05
python scripts/prove.py
```

`scripts/prove.py` submits six findings against that host and shows which survive.

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

## Evidence integrity

Read-only is enforced by absence, not by policy. No module in `collectors/` exposes a write,
shell, or execute verb, so there is no path — adversarial prompt or otherwise — that modifies
an image.

The store is append-only and hash-chained. Every entry commits to its predecessor, so editing
any earlier row breaks every hash after it, and `witness verify-chain` recomputes the lot.
Unlike ledgers that chain only the findings, the parsed records and the tool calls are in the
same chain, so evidence cannot be rewritten under a finding that already cites it. A broken
chain blocks every subsequent submission.

## Rejections are part of the output

Every claim stopped at either gate is written to the chain with the reason it died, and
`witness rejections` prints them. A report is worth more when you can see what did not make it
in — on the run above, one finding is admitted and eight are stopped, each with a recorded
refutation.

## Status

Slices 1 and 2 of a rebuild: the store, `psscan` / `netscan` / `malfind` collectors, both gates,
the ledger, retraction, and the rejection log.

Collectors run in replay mode — they ingest captured output carrying its evidence hash — which
is what makes the demo reproducible without a 3 GB image. Live mode is the same parsers behind a
subprocess call and lands with the wider collector set.

Known limits, stated rather than discovered later:

- `malfind`'s trailing `Hexdump` and `Disasm` columns are multi-line in Volatility's default
  renderer. The parser reads the tabular prefix and reports any line it cannot fit rather than
  dropping it silently; ingesting the CSV renderer instead is the proper fix. The empty-result
  fixture is a real capture, the with-hits fixture under `fixtures/synthetic/` is hand-written.
- The chain is recomputed in full on every submission. Correct, and fine at case scale; it will
  want an incremental check before it sees a large timeline.

Not yet built: disk and event-log collectors, indicator extraction, report generation, and the
adversarial test suite.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT.
