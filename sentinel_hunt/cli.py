"""Interactive log review and optional analyst-approved endpoint containment."""
import argparse
import json
import os
import sys
from pathlib import Path

from .findings import resolve
from .analysis import plan_search, review_events
from .query import Search
from .workspace import fetch_events

DEMO = Path(__file__).resolve().parents[1] / "examples" / "logon-review.json"


def show(findings):
    print(f"{len(findings)} finding(s)")
    for finding in findings:
        print(json.dumps(finding, indent=2, default=str, ensure_ascii=True))


def live(args):
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient
    from openai import OpenAI

    workspace = os.environ["LOG_ANALYTICS_WORKSPACE_ID"]
    question = input("Hunt question: ").strip()
    if not question:
        raise ValueError("Enter a hunt question")
    client = OpenAI()
    search = plan_search(client, args.model, question)
    print(f"Lookback: {search.hours} hours\n{search.kql()}")
    if input("Run this query? [y/N] ").strip().lower() != "y":
        return
    credential = DefaultAzureCredential()
    rows = fetch_events(LogsQueryClient(credential), workspace, search)
    if not rows:
        print("No events matched.")
        return
    numbered = [{"row": i, "event": row} for i, row in enumerate(rows, 1)]
    data = {"question": question, "table": search.table, "rows": numbered}
    size = len(json.dumps(data, default=str).encode())
    print(f"{len(rows)} event(s), {size:,} JSON bytes for {args.model}")
    if size > 100_000:
        raise ValueError("Evidence exceeds 100,000 bytes. Narrow the time window or target.")
    if input("Send these events to OpenAI for review? [y/N] ").strip().lower() != "y":
        return
    report = review_events(client, args.model, data)
    findings = resolve(report, rows)
    show(findings)
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump({"question": question, "query": search.kql(), "hours": search.hours,
                       "model": args.model, "rows_reviewed": len(rows), "findings": findings},
                      stream, indent=2, default=str)
    if (args.offer_isolation and search.table.startswith("Device") and search.target
            and any(f["confidence"] == "high" for f in findings)):
        import requests
        from .defender import BASE, isolate, resolve_machine
        with requests.Session() as session:
            token = credential.get_token(BASE + "/.default").token
            session.headers["Authorization"] = f"Bearer {token}"
            host = resolve_machine(session, search.target)
            dns = host["computerDnsName"]
            print(f"Full isolation target: {dns} ({host['id']})")
            if input("Type the full DNS name to request isolation: ") == dns:
                print("Isolation action submitted:", isolate(session, host["id"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="Replay a synthetic finding offline")
    parser.add_argument("--model", default="gpt-5-mini")
    parser.add_argument("--output", type=Path, help="Write live results to a new JSON file")
    parser.add_argument("--offer-isolation", action="store_true")
    args = parser.parse_args()
    if args.demo:
        fixture = json.loads(DEMO.read_text(encoding="utf-8"))
        print("Offline replay | synthetic events and a prewritten finding")
        print(Search(**fixture["plan"]).kql())
        show(resolve(fixture["report"], fixture["rows"]))
    else:
        live(args)


def run():
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        sys.exit("Cancelled.")
    except Exception as exc:
        sys.exit(f"Hunt stopped: {exc}")
