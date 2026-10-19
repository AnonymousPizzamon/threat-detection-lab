# Scripts

| Script | Purpose |
| --- | --- |
| attack_heatmap.py | Builds an ATT&CK Navigator layer from coverage.yml |
| validate_detections.py | After an atomic: checks Elasticsearch for telemetry and Kibana for the alert |
| sigma_to_eql.py | Converts Sigma rules to EQL with pySigma, optionally deploys them to Kibana |
| investigate.py | Pulls an alert's triggering and related events for pivoting |
| lab.py | Shared connection setup (reads `.env`) |

## Setup

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Fill in `.env` with the SIEM VM's address and an API key. Copy `/etc/elasticsearch/certs/http_ca.crt` off the Ubuntu VM and point `ES_CA_CERT` at it. Check the Elasticsearch major version (`curl https://<siem>:9200` shows it) and make sure the `elasticsearch` pin in `requirements.txt` matches.

## attack_heatmap.py

```
python scripts/attack_heatmap.py
```

Writes `coverage-layer.json`. Change a technique's status in `coverage.yml` (planned, emulated, detected), rerun, and upload the JSON in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## validate_detections.py

```
python scripts/validate_detections.py T1136.001
python scripts/validate_detections.py --all --since 2h
python scripts/validate_detections.py T1110.001 --wait 360
```

Read-only: run the atomic on the Windows VM first, then this. For each technique in `validations.yml` it runs the telemetry EQL against `logs-*` and asks the Detection Engine API (`/api/detection_engine/signals/search`) whether the named rule fired. Results append to `results/validation-results.jsonl`. Exit code 1 on any failure.

- `rule: null` means telemetry-only, so it can be used before the rule exists.
- Rules run every 5 minutes, so use `--wait` right after an atomic.
- `LAB_HOST` in `.env` limits checks to the Windows VM.

## sigma_to_eql.py

```
python scripts/sigma_to_eql.py
python scripts/sigma_to_eql.py --deploy
```

Converts every `detections/*/rule.sigma.yml` with the `ecs_windows` pipeline and writes `rule.eql.txt` next to it. `--deploy` creates or updates the rule in Kibana, keyed on the Sigma `id`. Rules that can't be converted (like a count-over-time rule) are skipped with the error; build those in Kibana by hand.

The converter uses `.caseless` fields (e.g. `process.executable.caseless`). If a converted query returns nothing in Kibana, check whether those fields exist in your index.

## investigate.py

```
python scripts/investigate.py <alert_id>
python scripts/investigate.py <alert_id> --pivot process --window 30
python scripts/investigate.py <alert_id> --out investigations/001-x/timeline.md --json investigations/001-x/raw.json
```

Pulls the alert, the raw event(s) it matched (`kibana.alert.ancestors`), and every event within `--window` minutes on the same host, user, or process tree. Prints a timeline, and optionally writes it as a markdown table for the investigation writeup. Get the alert ID from the alert details flyout in Kibana (the `_id` field).
