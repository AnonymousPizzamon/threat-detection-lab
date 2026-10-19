"""turns coverage.yml into an ATT&CK Navigator layer so I can see what the lab covers.

run: python scripts/attack_heatmap.py
(--coverage / --out if I ever move the files)

to view: https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer
-> Upload from local -> coverage-layer.json
"""

import argparse
import json
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent

# status -> (score, color, legend label); higher score = further along
STATUSES = {
    "planned": (1, "#d9d9d9", "Planned"),
    "emulated": (2, "#ffd966", "Emulated (atomic run, telemetry confirmed)"),
    "detected": (3, "#6aa84f", "Detected (rule validated by harness)"),
}


def load_coverage(path):
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    techniques = data.get("techniques") or []
    for t in techniques:
        if t.get("status") not in STATUSES:
            sys.exit(f"{t.get('id')}: unknown status {t.get('status')!r}, expected one of {list(STATUSES)}")
    return techniques


def build_layer(techniques, name):
    entries = []
    for t in techniques:
        score, color, label = STATUSES[t["status"]]
        entry = {
            "techniqueID": t["id"],
            "score": score,
            "color": color,
            "comment": label,
            "enabled": True,
            "showSubtechniques": False,
        }
        # without a tactic, Navigator highlights the technique under every tactic it belongs to
        if t.get("tactic"):
            entry["tactic"] = t["tactic"]
        entries.append(entry)

    counts = {s: sum(1 for t in techniques if t["status"] == s) for s in STATUSES}
    description = ", ".join(f"{n} {s}" for s, n in counts.items())

    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": f"Threat Detection Lab coverage: {description}",
        "sorting": 0,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {"colors": ["#ffffff", "#6aa84f"], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": label, "color": color} for _, color, label in STATUSES.values()],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--coverage", default=SCRIPT_DIR / "coverage.yml", type=Path)
    parser.add_argument("--out", default=SCRIPT_DIR / "coverage-layer.json", type=Path)
    parser.add_argument("--name", default="Threat Detection Lab Coverage")
    args = parser.parse_args()

    techniques = load_coverage(args.coverage)
    layer = build_layer(techniques, args.name)
    args.out.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(techniques)} techniques to {args.out}")
    print(layer["description"])


if __name__ == "__main__":
    main()
