"""witness - command line over the store, the gate and the ledger."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import report as report_module
from .collectors import decode, indicators, rawstrings
from .collectors.volatility import PLUGINS, ingest_capture
from .falsify import REGISTRY
from .replay import replay
from .store import Store
from .verify import Binding, revalidate, submit_finding

DEFAULT_STORE = "witness.db"
TOOLS = sorted([*PLUGINS, rawstrings.TOOL])


def _parse_binding(spec: str) -> Binding:
    if ":" not in spec or "=" not in spec:
        raise argparse.ArgumentTypeError(
            f"bad binding {spec!r}; expected RECORD_ID:field=value"
        )
    record_id, rest = spec.split(":", 1)
    field, value = rest.split("=", 1)
    return Binding(record_id=record_id, field=field, value=value)


def cmd_ingest(args: argparse.Namespace) -> int:
    store = Store(args.store)
    common = dict(
        output_path=args.input,
        host=args.host,
        evidence_path=args.evidence_path,
        evidence_sha256=args.evidence_sha256,
    )
    if args.tool == rawstrings.TOOL:
        result = rawstrings.ingest_capture(store, **common)
    else:
        result = ingest_capture(store, plugin_name=args.tool, **common)
    print(f"tool call   {result['tool_call_id']}  ({result['plugin']}, mode=replay)")
    print(f"output hash {result['output_sha256']}")
    print(f"records     {result['records']} of kind {result['kind']}")
    if result["skipped"]:
        print(f"skipped     {len(result['skipped'])} unparsable rows:")
        for line in result["skipped"]:
            print(f"  - {line}")
    print(f"chain head  {store.head()}")
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    store = Store(args.store)
    result = decode.unwrap(store, host=args.host)
    print(f"tool call     {result['tool_call_id']}  ({result['tool']}, mode=derived)")
    print(f"read          {result['sources']} record(s)")
    print(f"command lines {result['command_lines']}")
    print(
        f"blobs         {result['blobs']}"
        f"  ({result['superseded']} superseded as prefixes of a longer capture)"
    )
    print(f"payloads      {result['payloads']} decoded across {result['stages']} stage(s)")
    print(f"chain head    {store.head()}")
    return 0


def cmd_indicators(args: argparse.Namespace) -> int:
    store = Store(args.store)
    if args.extract:
        result = indicators.extract(store, host=args.host)
        by_type = ", ".join(f"{k}={v}" for k, v in sorted(result["by_type"].items())) or "none"
        print(f"tool call   {result['tool_call_id']}  ({result['tool']}, mode=derived)")
        print(f"read        {result['sources']} record(s)")
        print(f"indicators  {result['indicators']}  ({by_type})")
        print(f"            {result['in_execution_context']} seen in an execution context")
        print(f"chain head  {store.head()}")
        return 0

    rows = store.query_records(kind=indicators.KIND, host=args.host)
    if args.type:
        rows = [r for r in rows if r["fields"]["type"] == args.type]
    if args.executed:
        rows = [r for r in rows if r["fields"]["execution_context"]]
    for row in rows[: args.limit]:
        fields = row["fields"]
        marker = "executed" if fields["execution_context"] else "carved  "
        print(f"{marker}  {fields['type']:<7} {fields['value']}")
        print(f"          <- {fields['source_kind']} {fields['source_record_id']}")
    print(f"-- {len(rows)} indicator(s)")
    return 0


def cmd_provenance(args: argparse.Namespace) -> int:
    store = Store(args.store)
    record = store.get_record(args.record_id)
    if not record:
        print(f"no such record: {args.record_id}")
        return 1
    print(f"{record['record_id']}  [{record['kind']}]")
    print(f"  {json.dumps(record['fields'], sort_keys=True)[:200]}")
    for step, call in enumerate(store.provenance(args.record_id), start=1):
        argv = " ".join(json.loads(call["argv"]))
        print(f"  {step}. {call['tool']}  ({call['mode']})")
        print(f"     {argv}")
        if call["evidence_path"]:
            print(f"     evidence {call['evidence_path']}  sha256(output) {call['output_sha256'][:16]}...")
    return 0


def cmd_records(args: argparse.Namespace) -> int:
    store = Store(args.store)
    where = {}
    for pair in args.where or []:
        key, value = pair.split("=", 1)
        where[key] = value
    rows = store.query_records(kind=args.kind)
    if where:
        def matches(fields: dict) -> bool:
            return all(str(fields.get(k)) == v for k, v in where.items())

        rows = [r for r in rows if matches(r["fields"])]
    for row in rows[: args.limit]:
        print(f"{row['record_id']}  {json.dumps(row['fields'], sort_keys=True)}")
    print(f"-- {len(rows)} record(s){' (showing ' + str(args.limit) + ')' if len(rows) > args.limit else ''}")
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    store = Store(args.store)
    subject = {}
    for pair in args.subject or []:
        key, value = pair.split("=", 1)
        subject[key] = value
    verdict, finding_id = submit_finding(
        store,
        finding_type=args.type,
        claim=args.claim,
        bindings=args.bind,
        subject=subject,
    )
    print(verdict.report())
    if finding_id:
        print(f"  finding {finding_id} written to the ledger")
        return 0
    print("  nothing was written to the ledger")
    return 1


def cmd_types(args: argparse.Namespace) -> int:
    for name in sorted(REGISTRY):
        spec = REGISTRY[name]
        keys = ", ".join(spec.subject_keys) or "-"
        print(f"{name}\n    {spec.description}\n    subject keys: {keys}")
        for check in spec.checks:
            print(f"    check {check.name}: {check.rationale}")
    return 0


def cmd_revalidate(args: argparse.Namespace) -> int:
    store = Store(args.store)
    retracted = revalidate(store)
    for finding_id, reason in retracted:
        print(f"retracted {finding_id}")
        print(f"    {reason}")
    print(f"-- {len(retracted)} finding(s) retracted")
    return 0


def cmd_rejections(args: argparse.Namespace) -> int:
    store = Store(args.store)
    rejections = store.list_rejections()
    for item in rejections:
        print(f"[{item['finding_type']}] {item['claim']}")
        print(f"    {item['reason']}")
    print(f"-- {len(rejections)} claim(s) stopped at the gate")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    store = Store(args.store)
    findings = store.list_findings()
    for item in findings:
        print(f"{item['finding_id']}  [{item['finding_type']}] {item['claim']}")
        for binding in item["bindings"]:
            print(f"    <- {binding['record_id']} {binding['field']}={binding['value']}")
        for note in item["notes"]:
            print(f"    note: {note}")
    print(f"-- {len(findings)} finding(s) in the ledger")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = Store(args.store)
    built = report_module.build(store, host=args.host)
    text = (
        report_module.render_json(built)
        if args.format == "json"
        else report_module.render_markdown(built)
    )

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"report      {args.out}")
        print(f"sha256      {report_module.sha256_text(text)}")
    else:
        print(text, end="")

    if args.issue:
        if args.format == "json":
            print("refusing to issue a json rendering; issue the markdown report")
            return 1
        try:
            entry = report_module.issue(store, built, text)
        except ValueError as exc:
            print(str(exc))
            return 1
        print(f"issued      {entry['report_id']} from chain head {entry['chain_head']}")
        print(f"summary     {entry['summary']}")
    elif not built.issuable:
        return 1
    return 0


def cmd_verify_report(args: argparse.Namespace) -> int:
    store = Store(args.store)
    text = Path(args.file).read_text(encoding="utf-8")
    result = report_module.check_issued(store, text)

    print(f"report sha256  {result['report_sha256']}")
    if not result["issued"]:
        print("issued         NO - these bytes were never committed to this chain")
        print("               an issued report that has been edited by one character lands here")
        return 1
    print(f"issued         yes, from chain head {result['issued_from']}")
    print(f"current head   {result['current_head']}")
    print(f"still current  {result['still_current']}"
          + ("" if result["still_current"] else "  (the case has moved on since it was issued)"))
    print(f"still holds    {result['still_holds']}")
    for problem in result["problems"]:
        print(f"  - {problem}")
    return 0 if result["still_holds"] else 1


def cmd_replay(args: argparse.Namespace) -> int:
    source = Store(args.store)
    target = Path(args.into) if args.into else None
    if target and target.exists():
        print(f"refusing to replay into an existing store: {target}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        into = Store(target or Path(tmp) / "replayed.db")
        result = replay(source, args.inputs, into)
        print(result.report())
    return 0 if result.ok else 1


def cmd_verify_chain(args: argparse.Namespace) -> int:
    store = Store(args.store)
    ok, problems = store.verify_chain()
    if ok:
        print(f"chain intact, head {store.head()}")
        return 0
    print("chain BROKEN")
    for problem in problems:
        print(f"  - {problem}")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="witness", description=__doc__)
    parser.add_argument("--store", default=DEFAULT_STORE, help=f"store path (default {DEFAULT_STORE})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="parse captured tool output into records")
    p_ingest.add_argument("--tool", required=True, choices=TOOLS)
    p_ingest.add_argument("--input", required=True, help="captured tool output file")
    p_ingest.add_argument("--host")
    p_ingest.add_argument("--evidence-path")
    p_ingest.add_argument("--evidence-sha256")
    p_ingest.set_defaults(func=cmd_ingest)

    p_decode = sub.add_parser("decode", help="unwrap encoded payloads found in stored records")
    p_decode.add_argument("--host")
    p_decode.set_defaults(func=cmd_decode)

    p_ind = sub.add_parser("indicators", help="extract or list indicators")
    p_ind.add_argument("--extract", action="store_true", help="run the extractor over stored records")
    p_ind.add_argument("--host")
    p_ind.add_argument("--type", choices=["domain", "url", "ipv4", "md5", "sha1", "sha256"])
    p_ind.add_argument("--executed", action="store_true", help="only those seen in an execution context")
    p_ind.add_argument("--limit", type=int, default=100)
    p_ind.set_defaults(func=cmd_indicators)

    p_prov = sub.add_parser("provenance", help="walk a record back to the capture it came from")
    p_prov.add_argument("record_id")
    p_prov.set_defaults(func=cmd_provenance)

    p_records = sub.add_parser("records", help="query parsed records")
    p_records.add_argument("--kind")
    p_records.add_argument("--where", action="append", metavar="field=value")
    p_records.add_argument("--limit", type=int, default=50)
    p_records.set_defaults(func=cmd_records)

    p_submit = sub.add_parser("submit", help="submit a finding through both gates")
    p_submit.add_argument("--type", required=True, choices=sorted(REGISTRY))
    p_submit.add_argument("--claim", required=True)
    p_submit.add_argument("--bind", action="append", type=_parse_binding, default=[],
                          metavar="RECORD_ID:field=value")
    p_submit.add_argument("--subject", action="append", metavar="key=value",
                          help="what the finding is about; must be proved by a binding")
    p_submit.set_defaults(func=cmd_submit)

    p_types = sub.add_parser("types", help="list finding types and what would refute each")
    p_types.set_defaults(func=cmd_types)

    p_reval = sub.add_parser("revalidate", help="re-run every check and retract what now fails")
    p_reval.set_defaults(func=cmd_revalidate)

    p_rej = sub.add_parser("rejections", help="list claims stopped at the gate, and why")
    p_rej.set_defaults(func=cmd_rejections)

    p_findings = sub.add_parser("findings", help="list accepted findings")
    p_findings.set_defaults(func=cmd_findings)

    p_report = sub.add_parser("report", help="render the case from the ledger, re-checking as it goes")
    p_report.add_argument("--host", help="narrow the report to one machine")
    p_report.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_report.add_argument("--out", help="write to a file instead of stdout")
    p_report.add_argument("--issue", action="store_true",
                          help="commit the rendered report to the chain it came from")
    p_report.set_defaults(func=cmd_report)

    p_vreport = sub.add_parser("verify-report", help="was this report issued from this store, and does it still hold")
    p_vreport.add_argument("file")
    p_vreport.set_defaults(func=cmd_verify_report)

    p_replay = sub.add_parser("replay", help="re-derive the whole case from the captures and compare")
    p_replay.add_argument("--inputs", action="append", required=True, metavar="PATH",
                          help="directory or file holding the captured tool output")
    p_replay.add_argument("--into", help="keep the rebuilt store at this path")
    p_replay.set_defaults(func=cmd_replay)

    p_chain = sub.add_parser("verify-chain", help="recompute the audit chain")
    p_chain.set_defaults(func=cmd_verify_chain)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
