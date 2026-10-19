"""after running an atomic on the windows VM, checks that the telemetry landed in elasticsearch
and that the matching detection rule fired in kibana. read-only, never touches the VM.

run: python scripts/validate_detections.py T1136.001
     python scripts/validate_detections.py --all --since 2h
     python scripts/validate_detections.py T1110.001 --wait 360   (keep checking for the alert, rules run every 5m)

checks live in validations.yml. every run gets appended to results/validation-results.jsonl.
exit code is 1 if anything failed.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

import lab

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS = SCRIPT_DIR / "results" / "validation-results.jsonl"


def time_filter(since):
    filters = [{"range": {"@timestamp": {"gte": f"now-{since}"}}}]
    if lab.HOST:
        filters.append({"term": {"host.name": lab.HOST}})
    return {"bool": {"filter": filters}}


def check_telemetry(es, query, since):
    resp = es.eql.search(index=lab.INDEX, query=query, filter=time_filter(since), size=100)
    return len(resp["hits"].get("events", []))


def check_alert(rule, since):
    body = {
        "query": {"bool": {"filter": [
            {"term": {"kibana.alert.rule.name": rule}},
            *time_filter(since)["bool"]["filter"],
        ]}},
        "size": 0,
        "track_total_hits": True,
    }
    resp = lab.kibana("POST", "/api/detection_engine/signals/search", json=body)
    return resp["hits"]["total"]["value"] if resp else 0


def validate(es, technique, check, since, wait):
    events = check_telemetry(es, check["telemetry"], since)
    telemetry_ok = events >= check.get("min_events", 1)

    rule = check.get("rule")
    alerts = None
    if rule:
        deadline = time.monotonic() + wait
        alerts = check_alert(rule, since)
        while alerts == 0 and time.monotonic() < deadline:
            print(f"  {technique}: no alert yet, checking again in 30s...")
            time.sleep(30)
            alerts = check_alert(rule, since)

    # no rule yet = telemetry-only check
    passed = telemetry_ok and (alerts is None or alerts > 0)
    return {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "technique": technique,
        "telemetry_events": events,
        "rule": rule,
        "alerts": alerts,
        "result": "PASS" if passed else "FAIL",
    }


def main():
    parser = argparse.ArgumentParser(description="check telemetry + alerts after an atomic run")
    parser.add_argument("techniques", nargs="*", help="technique IDs from validations.yml")
    parser.add_argument("--all", action="store_true", help="check every technique in validations.yml")
    parser.add_argument("--since", default="30m", help="how far back to look, e.g. 30m, 2h (default 30m)")
    parser.add_argument("--wait", type=int, default=0, help="seconds to keep retrying a missing alert")
    parser.add_argument("--checks", default=SCRIPT_DIR / "validations.yml", type=Path)
    args = parser.parse_args()

    checks = yaml.safe_load(args.checks.read_text(encoding="utf-8"))["checks"]
    techniques = list(checks) if args.all else args.techniques
    if not techniques:
        parser.error("give one or more technique IDs, or --all")
    unknown = [t for t in techniques if t not in checks]
    if unknown:
        parser.error(f"not in {args.checks.name}: {', '.join(unknown)}")

    es = lab.es_client()
    results = [validate(es, t, checks[t], args.since, args.wait) for t in techniques]

    print(f"\n{'technique':<12} {'events':>6} {'alerts':>6}  {'rule':<40} result")
    for r in results:
        alerts = "-" if r["alerts"] is None else r["alerts"]
        print(f"{r['technique']:<12} {r['telemetry_events']:>6} {alerts:>6}  {(r['rule'] or '(no rule yet)'):<40} {r['result']}")

    RESULTS.parent.mkdir(exist_ok=True)
    with RESULTS.open("a", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    sys.exit(0 if all(r["result"] == "PASS" for r in results) else 1)


if __name__ == "__main__":
    main()
