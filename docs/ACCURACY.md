# Accuracy

Reproduce everything below with:

```
python scripts/accuracy.py
```

It exits non-zero if any claim lands on the wrong side, and it prints the case
list, not just the totals.

## What is being measured, and why not the usual thing

The usual accuracy report for a tool like this takes one case, states that no
hallucinated finding survived, and stops. That number has no denominator. Nobody
attempted a wrong claim, so nothing was resisted, and a tool that refuses
everything scores exactly the same.

So this measures two things together, and publishes both:

- **Precision** — of what it admitted, how much the evidence supports. This is
  the number that looks good for free.
- **Recall** — of what the evidence supports, how much it admitted. This is the
  bill for the first one, and it is where an over-cautious tool falls over.

And a third that is rarer and matters more:

- **Reason** — of the claims it refused, how many refusals named the thing that
  is actually wrong, rather than a true statement about something else. A claim
  stopped for a reason that is not the reason it is wrong was stopped by
  accident, and an accident does not repeat on the case you have not seen.

## The evidence

SANS SRL-2018, the "Compromised Enterprise Network" set. Two hosts:

- `base-wkstn-01` — Windows 10 1709, captured 2021-09-16, a clean baseline.
- `base-wkstn-05` — Windows 7 SP1 x64, `172.16.7.15`, captured 2018-09-06, the
  workstation with the intrusion on it.

Six captures, 347 records: `windows.info`, `windows.netscan` and
`windows.malfind` on the clean host; `windows.psscan`, `windows.netscan` and a
raw string carve on the compromised one; then `decode.unwrap` and
`indicators.extract` derived from the carve.

This is the whole of the exported evidence, not a sample of it. There is no
third host to scale onto — the memory images are 3 GB each and are not ours to
redistribute, and what is in this repository is the captured tool output carried
with the SHA-256 of the image it came from.

## The corpus

1,083 claims across 29 error classes. 519 the evidence supports and 564 it does
not, so both halves are populated and neither number can be gamed by leaning on
the other.

Two rules keep it honest.

**The labels come from the capture text, not from the store.** Every claimed
value is read off the captured tool output by a separate reader in
`tests/corpus.py`, never asked of the record it will be checked against. A
corpus that asked witness what a record says and then tested whether witness
agreed would let a parser grade its own mistake as correct.

**Every row is covered.** The census classes line each raw row up with the
record it became, by position. A row the collector dropped, duplicated or
reordered puts every later pair out of step, and the run fails loudly instead of
generating one case fewer and still reporting a clean sweep. There is a test for
that failing (`test_a_dropped_row_breaks_the_census_rather_than_shrinking_it`),
because a harness that cannot fail is not measuring anything.

## Results

- precision 100% — of 519 admitted findings, 519 were supported
- recall 100% — of 519 supported claims, 519 were admitted
- reason 100% — of 564 refusals, 564 named the actual defect

Per class, in the order the run prints them. Every one scored complete.

Claims the evidence supports, and that were admitted:

- `field_census_captured` (245) — every field of every parsed row of every
  capture, re-asserted from the capture text
- `field_census_strings` (40) — every non-blank line of the raw carve, by line
  number and text
- `field_census_derived` (62) — every field of every derived record,
  round-tripped
- `sound_process_present` (57) — each process in the listing, claimed as present
- `sound_process_chain` (1) — the intrusion's kill chain, every link bound
- `sound_executed_domain` (1) — a domain recovered from something that executed
- `sound_encoded_payload` (2) — a payload claim made against a blob this store
  decoded
- `tolerance_case_fold` (54) — the same process name in the wrong case
- `tolerance_surrounding_space` (57) — the right value with whitespace around it

Claims the evidence does not support, and that were refused:

- `transposed_pid` (56) — a PID with its digits reversed
- `misread_image_name` (57) — a process name with one character dropped
- `field_confusion` (57) — the parent's PID asserted as the process's own
- `truncation_overreach` (7) — a name completed past the width the evidence holds
- `phantom_record` (4) — a citation shaped like a citation, pointing at nothing
- `dropped_octet` (19) — an address with an octet mis-read
- `transposed_port` (19) — a port with its digits reversed
- `internal_peer_as_c2` (76) — an RFC1918 peer called external command and control
- `unaddressable_peer_as_c2` (92) — a listening socket's wildcard peer, same claim
- `injection_without_malfind` (57) — an injection claim on the host where malfind
  was never run
- `injection_refuted_by_empty_malfind` (17) — an injection claim on the host where
  malfind ran and returned nothing
- `process_claim_without_listing` (17) — a process claim on a host with no process
  listing ingested
- `internal_domain_as_c2` (1) — a name that cannot resolve on the internet
- `carved_domain_as_c2` (5) — a domain in the image but in nothing that ran
- `undecoded_blob_as_payload` (4) — what a blob contains, asserted without decoding it
- `subject_drift` (57) — bindings that verify, about a subject none of them proves
- `unbacked_conclusion` (4) — a confident sentence with no citation under it
- `cross_host_bindings` (6) — one finding drawing evidence from two machines
- `host_mismatch` (6) — a finding naming a host its evidence did not come from
- `unregistered_finding_type` (3) — a conclusion no registered check can try to
  disprove

## How to read 1,083

It is classes times records. An error class is applied to every record it can
apply to, so 57 process rows carrying one error class is 57 cases, and those 57
are not 57 independent experiments. The per-class list above is the honest way
to read the total.

What the total does mean is a census: every row of every capture in this case
has been through the gate, in both directions.

One number in the run is smaller than it looks the other way. 564 claims were
refused and 406 rejection entries were written, because a rejection is
identified by what it is — the type, the claim, and the reason it died — so the
same claim refused the same way twice is one line rather than two. That is
deliberate, a report should not print the same refusal ninety times, and it is
said out loud because a count that quietly deduplicates reads higher than it is.

## What the percentages cannot see

Supported by this evidence and true about this intrusion are two different axes,
and only the first is scored above. Where they come apart on this case:

- **`www.venetodns.trade` is the intrusion's real command and control, and this
  tool refuses it.** In the exported captures the name appears in a raw string
  carve and in nothing that executed, so `malicious_domain` holds it as unproven
  and names the remedy. On this evidence that is the right answer; on this case
  it is a miss. Ingest the PowerShell command that carries the name — it exists,
  in the disk image's Sysmon and PowerShell logs — and the same claim is
  admitted. The gap is in what was exported, and the refusal says so rather than
  splitting the difference.
- **The entry vector is not claimable at all.** PSRemoting under a stolen SQL
  service account, reaching `wsmprovhost`, lives in disk artefacts that were
  never exported. There is no claim about it to admit or refuse. That is a gap
  in what this repository can be pointed at, not a decision the gate made.
- **In the other direction:** decoding the carved stager recovers
  `aaa.stage.9231829.extranet.wagonwheelgifts.com`, a DNS-beacon hostname
  embedded in the second-stage shellcode, in something that ran. It is admitted,
  and it does not appear in the graded run this project was built to improve on.
  Decoding rather than describing found a C2 that reading the carve did not.
- **`base-wkstn-01` has nothing to miss.** It is a clean baseline. The accuracy
  result that matters on a clean host is that every attempt in this corpus to
  make it look compromised was refused — 59 of them — while 76 supported
  observations about it were admitted.

## Other limits, stated

- **Two hosts.** Not because two is enough, but because two is what was
  exported. No claim is made about how this behaves on a third.
- **Memory only.** No MFT, no EVTX, no registry, no prefetch. The collectors for
  those are unbuilt because there is nothing in the captured set to point them
  at, and building a collector with no evidence to test it against is how you
  get a collector that has never been wrong because it has never run.
- **There is not one routable foreign address in either host's connection
  table.** Every peer is RFC1918, loopback or a wildcard. So the 168 network
  claims in the corpus are all refusals, and the admitting branch of the
  `external_c2` predicate is exercised by unit tests rather than by this case. A
  100% score on `internal_peer_as_c2` is a real result about a real failure mode
  — it is exactly the false positive the graded baseline produced — but it is
  not evidence that a true external C2 would be admitted.
- **The derived census is a round trip.** Values written by `decode.unwrap` and
  `indicators.extract` have no source outside this tool, so re-reading them
  shows that a record the gate can cite is a record the gate can read back, and
  nothing stronger.
- **Two tolerances are deliberate.** A case-only difference in a process name is
  admitted with a note in the ledger, because `WMIPRVSE.EXE` and `WmiPrvSE.exe`
  are the same Windows object. Surrounding whitespace is stripped. Everything
  else compares exactly: a truncated name, a zero-width space, a substring, a
  superstring and a PID off by an octet are all refused, and
  `tests/adversarial.py` holds those cases.
- **The chain is re-verified on every submission**, so a run of a thousand
  claims costs about thirty seconds and the cost grows with the square of the
  case. That is a real ceiling on case size, and it buys the property that no
  finding is ever admitted against a store whose history has been altered.

## The defect this found

Writing the corpus turned up one, and it is fixed rather than documented.

Fifty-seven claims in the `subject_drift` class were refused correctly and
recorded for the wrong reason. Their bindings verified, so the falsification
checks ran — against the drifted subject — and truthfully reported that no
process row exists for PID 13720. That went into the ledger as the reason the
finding died. The reason it actually died is that its subject is not proved by
any binding it carries; the check was answering a real question about the wrong
process.

`Verdict.refutation` now orders cause before consequence: a binding that does
not verify, then anything wrong with how the finding is put together, and only
then the checks. It cost nothing in accuracy — the decisions were already right
— and it is the difference between a ledger that sends the next reader to the
claim and one that sends them looking for a process that was never there.
