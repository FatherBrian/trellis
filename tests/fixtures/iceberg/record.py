"""Record Iceberg REST responses from live local catalogs for the adapter tests."""

import json
import re
import sys
from pathlib import Path

from trellisd.iceberg import IcebergRestAdmin, urllib_transport

name, uri, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
warehouse = sys.argv[4] if len(sys.argv) > 4 else None
token = Path(sys.argv[5]).read_text().strip() if len(sys.argv) > 5 else None
base = urllib_transport()
log = []


def rec(method, url, headers, body):
    status, raw = base(method, url, headers, body)
    if method == "GET":
        b = json.loads(raw) if raw else None
        if isinstance(b, dict) and "error" in b:
            b["error"].pop("stack", None)
        log.append((url[len(uri) :], status, b))
    return status, raw


adm = IcebergRestAdmin(uri, warehouse=warehouse, token=token, transport=rec)
T = "finance.gl.journal_entries"
adm.drop_table(T)
adm.create_namespace("finance.gl")
adm.create_table(
    T,
    {
        "entry_id": "string",
        "amount": "decimal(18,2)",
        "region": "string",
        "approver_email": "string",
    },
    {"trellis.tags": "finance"},
)
steps = {}
adm.load_table(T)
steps["01-created"] = log[-1]
adm.tag_column(T, "approver_email", "pii")
adm.load_table(T)
steps["02-column-tagged"] = log[-1]
adm.add_column(T, "notes")
adm.load_table(T)
steps["03-column-added"] = log[-1]
adm.tag_table(T, "finance", "confidential")
adm.load_table(T)
steps["04-table-level"] = log[-1]
adm.client.request("GET", "/v1" + adm.client.prefix() + "/namespaces/finance%1Fgl/tables/missing")
steps["05-missing"] = log[-1]
config = next(entry for entry in log if "/v1/config" in entry[0])
out.mkdir(parents=True, exist_ok=True)


def scrub(o):
    s = json.dumps(o, indent=1, sort_keys=True)
    s = re.sub(r"/tmp/iceberg_warehouse\d+", "/tmp/iceberg_warehouse", s)
    return s


(out / "config.json").write_text(
    scrub({"path": config[0], "status": config[1], "body": config[2]}) + "\n"
)
for k, (path, status, body) in steps.items():
    (out / f"{k}.json").write_text(scrub({"path": path, "status": status, "body": body}) + "\n")
(out / "README.md").write_text(
    f"Responses recorded from {name} running locally, by tests/fixtures/iceberg/record.py.\n"
)
print(name, sorted(p.name for p in out.iterdir()))
