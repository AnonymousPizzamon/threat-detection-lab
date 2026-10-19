"""pivot helper for investigations. give it an alert ID (from the kibana alerts table -> alert details -> _id)
and it pulls the alert, the raw event(s) that triggered it, and everything around it on the same
host / user / process tree, as one timeline.

run: python scripts/investigate.py <alert_id>
     python scripts/investigate.py <alert_id> --pivot user --window 30
     python scripts/investigate.py <alert_id> --pivot process --out investigations/001-.../timeline.md

not a SOAR, just saves re-typing the same queries in Discover.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import lab
from lab import get_field

COLUMNS = [
    ("time", "@timestamp"),
    ("code", "event.code"),
    ("action", "event.action"),
    ("user", "user.name"),
    ("process", "process.name"),
    ("parent", "process.parent.name"),
    ("command line", "process.command_line"),
    ("dest", "destination.ip"),
]


def fetch_alert(alert_id):
    body = {"query": {"ids": {"values": [alert_id]}}, "size": 1}
    resp = lab.kibana("POST", "/api/detection_engine/signals/search", json=body)
    hits = resp["hits"]["hits"] if resp else []
    if not hits:
        sys.exit(f"no alert with _id {alert_id}")
    return hits[0]["_source"]


def fetch_ancestors(es, alert):
    """the raw source events the rule matched on."""
    events = []
    for anc in get_field(alert, "kibana.alert.ancestors") or []:
        if anc.get("depth", 0) != 0:
            continue
        doc = es.get(index=anc["index"], id=anc["id"])
        events.append(doc["_source"])
    return events


def pivot_filter(pivot, alert, trigger):
    if pivot == "host":
        value = get_field(alert, "host.name")
        return value and {"term": {"host.name": value}}
    if pivot == "user":
        value = get_field(alert, "user.name")
        return value and {"term": {"user.name": value}}
    # process: the triggering process, its children, and its parent
    entity = get_field(trigger, "process.entity_id")
    parent = get_field(trigger, "process.parent.entity_id")
    should = [{"term": {"process.entity_id": entity}}, {"term": {"process.parent.entity_id": entity}}]
    if parent:
        should.append({"term": {"process.entity_id": parent}})
    return entity and {"bool": {"should": should, "minimum_should_match": 1}}


def related_events(es, pivot_query, center, window, size):
    start = (center - timedelta(minutes=window)).isoformat()
    end = (center + timedelta(minutes=window)).isoformat()
    resp = es.search(
        index=lab.INDEX,
        query={"bool": {"filter": [pivot_query, {"range": {"@timestamp": {"gte": start, "lte": end}}}]}},
        sort=[{"@timestamp": "asc"}],
        size=size,
    )
    return [h["_source"] for h in resp["hits"]["hits"]], resp["hits"]["total"]["value"]


def cell(event, field, width=None, md=False):
    value = get_field(event, field)
    if isinstance(value, list):
        value = ",".join(map(str, value))
    text = "" if value is None else str(value).replace("\n", " ")
    if md:
        text = text.replace("|", "\\|")
    return text[: width - 3] + "..." if width and len(text) > width else text


def print_table(events):
    print(f"{'time':<24} {'code':<5} {'user':<15} {'process':<20} command line")
    for e in events:
        print(f"{cell(e, '@timestamp'):<24} {cell(e, 'event.code'):<5} {cell(e, 'user.name', 15):<15} "
              f"{cell(e, 'process.name', 20):<20} {cell(e, 'process.command_line', 90)}")


def markdown_table(events):
    lines = ["| " + " | ".join(c for c, _ in COLUMNS) + " |", "|" + " --- |" * len(COLUMNS)]
    for e in events:
        lines.append("| " + " | ".join(cell(e, f, 150, md=True) for _, f in COLUMNS) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="pull an alert and the events around it")
    parser.add_argument("alert_id")
    parser.add_argument("--pivot", choices=["host", "user", "process"], default="host")
    parser.add_argument("--window", type=int, default=15, help="minutes either side of the alert (default 15)")
    parser.add_argument("--size", type=int, default=200, help="max related events (default 200)")
    parser.add_argument("--out", type=Path, help="write the timeline as a markdown table here")
    parser.add_argument("--json", type=Path, help="dump alert + raw events + timeline as JSON here")
    args = parser.parse_args()

    es = lab.es_client()
    alert = fetch_alert(args.alert_id)
    triggers = fetch_ancestors(es, alert)
    trigger = triggers[0] if triggers else alert
    center = datetime.fromisoformat(
        str(get_field(alert, "kibana.alert.original_time") or get_field(alert, "@timestamp")).replace("Z", "+00:00"))

    print(f"rule:     {get_field(alert, 'kibana.alert.rule.name')}")
    print(f"severity: {get_field(alert, 'kibana.alert.severity')}")
    print(f"time:     {center.isoformat()}")
    print(f"host:     {get_field(alert, 'host.name')}    user: {get_field(alert, 'user.name')}")
    print(f"\n== triggering event(s): {len(triggers)}")
    print_table(triggers)

    query = pivot_filter(args.pivot, alert, trigger)
    if not query:
        sys.exit(f"\nthe alert has no value to pivot on for --pivot {args.pivot}, try another pivot")
    events, total = related_events(es, query, center, args.window, args.size)
    print(f"\n== {args.pivot} pivot, +/-{args.window}m: showing {len(events)} of {total}")
    print_table(events)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(markdown_table(events), encoding="utf-8")
        print(f"\nwrote {args.out}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"alert": alert, "triggers": triggers, "timeline": events},
                                        indent=2, default=str), encoding="utf-8")
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
