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
witness ingest --tool strings --input fixtures/wkstn05/strings.txt --host base-wkstn-05
witness decode --host base-wkstn-05
witness indicators --extract --host base-wkstn-05
python scripts/prove.py
```

`scripts/prove.py` submits thirteen findings across two hosts and shows which survive.

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

## Evidence integrity

Read-only is enforced by absence, not by policy. No module in `collectors/` exposes a write,
shell, or execute verb, so there is no path — adversarial prompt or otherwise — that modifies
an image.

The store is append-only and hash-chained. Every entry commits to its predecessor, so editing
any earlier row breaks every hash after it, and `witness verify-chain` recomputes the lot.
Unlike ledgers that chain only the findings, the parsed records and the tool calls are in the
same chain, so evidence cannot be rewritten under a finding that already cites it. A broken
chain blocks every subsequent submission.

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

Slices 1 to 3 of a rebuild: the store, `psscan` / `netscan` / `malfind` / `strings` collectors,
the payload decoder, the indicator oracle, both gates, the ledger, retraction, the rejection
log, and the provenance walk. No runtime dependencies — the only bundled data is the IANA TLD
list.

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
- The chain is recomputed in full on every submission. Correct, and fine at case scale; it will
  want an incremental check before it sees a large timeline.

Not yet built: disk and event-log collectors, report generation, and the adversarial test suite.
There is a specific reason the first of those is absent rather than stubbed. The SRL-2018 case
does have a disk image with Sysmon and PowerShell Operational logs, and they would corroborate
this host's execution chain — but no export of them exists in the captured evidence set here.
A collector with no evidence behind it is a claim about coverage, and this repo's whole argument
is that those get marked unavailable rather than shipped.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT.
