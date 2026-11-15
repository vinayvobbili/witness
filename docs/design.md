# Design and status

Scope, evidence integrity, rejections as output, and what is built so far. Back to the [README](../README.md).

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

