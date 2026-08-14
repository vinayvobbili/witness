"""witness - command line over the store, the gate and the ledger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .collectors.volatility import PLUGINS, ingest_capture
from .falsify import REGISTRY
from .store import Store
from .verify import Binding, revalidate, submit_finding

DEFAULT_STORE = "witness.db"


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
    result = ingest_capture(
        store,
        plugin_name=args.tool,
        output_path=args.input,
        host=args.host,
        evidence_path=args.evidence_path,
        evidence_sha256=args.evidence_sha256,
    )
    print(f"tool call   {result['tool_call_id']}  ({result['plugin']}, mode=replay)")
    print(f"output hash {result['output_sha256']}")
    print(f"records     {result['records']} of kind {result['kind']}")
    if result["skipped"]:
        print(f"skipped     {len(result['skipped'])} unparsable rows:")
        for line in result["skipped"]:
            print(f"  - {line}")
    print(f"chain head  {store.head()}")
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
    p_ingest.add_argument("--tool", required=True, choices=sorted(PLUGINS))
    p_ingest.add_argument("--input", required=True, help="captured tool output file")
    p_ingest.add_argument("--host")
    p_ingest.add_argument("--evidence-path")
    p_ingest.add_argument("--evidence-sha256")
    p_ingest.set_defaults(func=cmd_ingest)

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

    p_chain = sub.add_parser("verify-chain", help="recompute the audit chain")
    p_chain.set_defaults(func=cmd_verify_chain)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
