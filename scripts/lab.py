"""shared connection setup for the lab scripts. settings come from .env in the repo root (see .env.example)."""

import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")

INDEX = os.getenv("LAB_INDEX", "logs-*")
HOST = os.getenv("LAB_HOST") or None


def _require(name):
    value = os.getenv(name)
    if not value:
        sys.exit(f"{name} is not set. Copy .env.example to .env and fill it in.")
    return value


def _verify(ca_var):
    """CA file path if one is set, otherwise True/False from VERIFY_TLS."""
    ca = os.getenv(ca_var)
    if ca:
        return ca
    return os.getenv("VERIFY_TLS", "true").lower() != "false"


def es_client():
    verify = _verify("ES_CA_CERT")
    kwargs = {"request_timeout": 30}
    if isinstance(verify, str):
        kwargs["ca_certs"] = verify
    else:
        kwargs["verify_certs"] = verify
        kwargs["ssl_show_warn"] = verify
    if os.getenv("ES_API_KEY"):
        kwargs["api_key"] = os.getenv("ES_API_KEY")
    else:
        kwargs["basic_auth"] = (_require("ES_USER"), _require("ES_PASS"))
    return Elasticsearch(_require("ES_URL"), **kwargs)


def kibana(method, path, **kwargs):
    """call the Kibana API and return the parsed JSON. raises on HTTP errors except 404 (returns None)."""
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    auth = None
    if os.getenv("ES_API_KEY"):
        headers["Authorization"] = f"ApiKey {os.getenv('ES_API_KEY')}"
    else:
        auth = (_require("ES_USER"), _require("ES_PASS"))
    url = _require("KIBANA_URL").rstrip("/") + path
    resp = requests.request(method, url, headers=headers, auth=auth,
                            verify=_verify("KIBANA_CA_CERT"), timeout=30, **kwargs)
    if resp.status_code == 404:
        return None
    if not resp.ok:
        sys.exit(f"Kibana {method} {path} -> {resp.status_code}: {resp.text[:500]}")
    return resp.json()


def get_field(doc, dotted):
    """read a field whether the doc stores it nested ({"host": {"name": ...}}) or flat ("host.name")."""
    if not isinstance(doc, dict):
        return None
    if dotted in doc:
        return doc[dotted]
    head, _, rest = dotted.partition(".")
    while rest:
        if head in doc:
            found = get_field(doc[head], rest)
            if found is not None:
                return found
        nxt, _, rest = rest.partition(".")
        head = f"{head}.{nxt}"
    return None
