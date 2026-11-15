#!/usr/bin/env python3
"""Build the payload of a signed "indicators" bundle from local files (offline).

Pipeline: read candidate malicious SHA-256 values -> normalize -> drop any hash
on the known-good list -> drop revoked IDs -> write payload JSON. Then sign the
payload with tools/hannibal_sign.py (bundle + sign).

LICENSING: check the terms of every feed before redistributing hashes from it.
Several abuse.ch feeds require a commercial licence for for-profit use; NSRL
and CIRCL hashlookup are known-good references. This tool does not download
anything - provide feed exports you are entitled to use.

Input CSV columns: indicator_id,sha256[,valid_days][,source]
Known-good file: one SHA-256 per line (comments with #).
"""
from __future__ import annotations

import argparse
import csv
import json
import pathlib
import re
import time

SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def load_known_good(path: str | None) -> set[str]:
    if not path:
        return set()
    out = set()
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if SHA256.match(line):
            out.add(line.lower())
    return out


def build(rows: list[dict], known_good: set[str], revoked: set[str], now_ms: int,
          default_days: float = 30) -> tuple[dict, dict]:
    seen, indicators = set(), []
    report = {"input": len(rows), "invalid": 0, "known_good_dropped": 0, "duplicates": 0, "kept": 0}
    for r in rows:
        iid, sha = (r.get("indicator_id") or "").strip(), (r.get("sha256") or "").strip().lower()
        if not iid or not SHA256.match(sha):
            report["invalid"] += 1
            continue
        if sha in known_good:
            report["known_good_dropped"] += 1
            continue
        if sha in seen:
            report["duplicates"] += 1
            continue
        seen.add(sha)
        days = float(r.get("valid_days") or default_days)
        item = {"indicator_id": iid, "sha256": sha, "valid_until_ms": now_ms + int(days * 86_400_000)}
        if r.get("source"):
            item["source"] = r["source"].strip()
        indicators.append(item)
    indicators.sort(key=lambda i: i["indicator_id"])
    report["kept"] = len(indicators)
    return {"indicators": indicators, "revoked": sorted(revoked)}, report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--candidates", help="CSV of candidate indicators")
    ap.add_argument("--known-good", help="file of known-good SHA-256 values")
    ap.add_argument("--revoke", action="append", default=[], help="indicator id to revoke (repeatable)")
    ap.add_argument("--eicar-only", action="store_true", help="beta default: only the EICAR test-file hash")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.eicar_only:
        rows = [{"indicator_id": "eicar-test-file", "sha256": EICAR_SHA256, "source": "EICAR anti-malware test file"}]
    elif a.candidates:
        with open(a.candidates, newline="") as f:
            rows = list(csv.DictReader(f))
    else:
        ap.error("--candidates or --eicar-only is required")
    payload, report = build(rows, load_known_good(a.known_good), set(a.revoke), int(time.time() * 1000))
    pathlib.Path(a.out).write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
