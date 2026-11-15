# How it works

The gate, the second gate, decoding, the domain stack, the report. Back to the [README](../README.md).

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

