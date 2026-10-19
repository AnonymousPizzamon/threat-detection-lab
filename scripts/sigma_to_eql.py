"""converts each detections/*/rule.sigma.yml to EQL with pySigma (ecs_windows pipeline)
and writes rule.eql.txt next to it. --deploy also creates/updates the rule in kibana,
using the sigma id as the kibana rule_id so redeploying updates instead of duplicating.

run: python scripts/sigma_to_eql.py                     (convert all)
     python scripts/sigma_to_eql.py detections/T1027-encoded-powershell/rule.sigma.yml
     python scripts/sigma_to_eql.py --deploy

if a rule can't be converted (e.g. the failed logon burst needs a count over time),
it gets skipped with the error. build that one as a threshold rule in kibana by hand.
"""

import argparse
import sys
from pathlib import Path

from sigma.backends.elasticsearch import EqlBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.elasticsearch.windows import ecs_windows

import lab

DETECTIONS = lab.REPO_ROOT / "detections"

# sigma level -> (kibana severity, risk score)
LEVELS = {
    "informational": ("low", 21),
    "low": ("low", 21),
    "medium": ("medium", 47),
    "high": ("high", 73),
    "critical": ("critical", 99),
}


def convert(backend, path):
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    queries = backend.convert(collection)
    if len(collection.rules) != 1 or len(queries) != 1:
        raise SigmaError(f"expected exactly one rule and one query, got {len(collection.rules)} / {len(queries)}")
    return collection.rules[0], queries[0]


def kibana_rule(rule, query):
    level = rule.level.name.lower() if rule.level else "medium"
    severity, risk = LEVELS[level]
    return {
        "rule_id": str(rule.id),
        "name": rule.title,
        "description": rule.description or rule.title,
        "type": "eql",
        "language": "eql",
        "query": query,
        "index": [lab.INDEX],
        "severity": severity,
        "risk_score": risk,
        "interval": "5m",
        "from": "now-6m",
        "enabled": True,
        "false_positives": [str(fp) for fp in rule.falsepositives or []],
        "references": [str(r) for r in rule.references or []],
        "author": [rule.author] if rule.author else [],
        "tags": ["sigma"] + [str(t) for t in rule.tags or []],
    }


def deploy(body):
    existing = lab.kibana("GET", "/api/detection_engine/rules", params={"rule_id": body["rule_id"]})
    if existing:
        lab.kibana("PUT", "/api/detection_engine/rules", json=body)
        return "updated"
    lab.kibana("POST", "/api/detection_engine/rules", json=body)
    return "created"


def main():
    parser = argparse.ArgumentParser(description="convert sigma rules to EQL, optionally deploy to kibana")
    parser.add_argument("rules", nargs="*", type=Path, help="specific rule.sigma.yml files (default: all)")
    parser.add_argument("--deploy", action="store_true", help="create/update the rules in kibana")
    args = parser.parse_args()

    paths = args.rules or sorted(DETECTIONS.glob("*/rule.sigma.yml"))
    if not paths:
        sys.exit(f"no rule.sigma.yml files under {DETECTIONS}")

    backend = EqlBackend(processing_pipeline=ecs_windows())
    failed = 0
    for path in paths:
        name = path.parent.name
        try:
            rule, query = convert(backend, path)
        except (SigmaError, NotImplementedError) as e:
            print(f"SKIP {name}: {e}")
            failed += 1
            continue

        out = path.with_name("rule.eql.txt")
        out.write_text(query + "\n", encoding="utf-8")
        print(f"OK   {name} -> {out.name}\n     {query}")

        if args.deploy:
            print(f"     kibana: {deploy(kibana_rule(rule, query))} '{rule.title}'")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
