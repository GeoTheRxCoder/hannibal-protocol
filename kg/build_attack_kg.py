"""Build Hannibal's local threat knowledge graph (offline).

Pattern borrowed from DeepSeek-Lattice-KG (Shu et al., 2026): keep domain
knowledge in an updatable graph rather than in model weights, and validate
every generated statement against it. Here the graph is built from the MITRE
ATT&CK Enterprise STIX 2.1 bundle (download enterprise-attack.json yourself
from MITRE's attack-stix-data repository) plus Hannibal's curated rule map.

Output: a SQLite file with kg_nodes / kg_edges / rule_refs. Only the
ThreatAnalysis explanation layer reads it. It has no action authority, and a
reference that does not resolve in the graph is dropped, not guessed.

Handles both the pre-v18 data model (x-mitre-data-source/-component and
"detects" relationships) and v18+ (x-mitre-detection-strategy, x-mitre-analytic).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3

KEEP = {
    "attack-pattern": "Technique", "x-mitre-tactic": "Tactic", "course-of-action": "Mitigation",
    "x-mitre-data-component": "DataComponent", "x-mitre-data-source": "DataSource",
    "x-mitre-detection-strategy": "DetectionStrategy", "x-mitre-analytic": "Analytic",
    "intrusion-set": "Group", "malware": "Software", "tool": "Software",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS kg_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kg_nodes(
  stix_id TEXT PRIMARY KEY, node_type TEXT NOT NULL, external_id TEXT, name TEXT NOT NULL,
  description TEXT, tactics TEXT, url TEXT);
CREATE INDEX IF NOT EXISTS ix_kg_ext ON kg_nodes(external_id);
CREATE TABLE IF NOT EXISTS kg_edges(src TEXT NOT NULL, relation TEXT NOT NULL, dst TEXT NOT NULL,
  PRIMARY KEY(src, relation, dst));
CREATE TABLE IF NOT EXISTS rule_refs(rule_id TEXT NOT NULL, ref_kind TEXT NOT NULL, ref_id TEXT NOT NULL,
  label TEXT NOT NULL, resolved INTEGER NOT NULL CHECK(resolved IN (0,1)), PRIMARY KEY(rule_id, ref_kind, ref_id));
"""


def _ext(obj: dict) -> tuple[str | None, str | None]:
    for r in obj.get("external_references", []):
        if r.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            return r.get("external_id"), r.get("url")
    return None, None


def build(bundle: dict, rule_map: dict, out_path: str) -> dict:
    objs = [o for o in bundle.get("objects", [])
            if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    db = sqlite3.connect(out_path)
    db.executescript(SCHEMA)
    db.execute("DELETE FROM kg_nodes"); db.execute("DELETE FROM kg_edges"); db.execute("DELETE FROM rule_refs")
    ids, stats = set(), {"nodes": 0, "edges": 0, "unresolved_refs": []}
    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), None)
    for o in objs:
        kind = KEEP.get(o["type"])
        if not kind:
            continue
        ext, url = _ext(o)
        tactics = ",".join(p["phase_name"] for p in o.get("kill_chain_phases", [])
                           if p.get("kill_chain_name", "").startswith("mitre"))
        db.execute("INSERT OR REPLACE INTO kg_nodes VALUES(?,?,?,?,?,?,?)",
                   (o["id"], kind, ext, o.get("name", ext or o["id"]), (o.get("description") or "")[:2000],
                    tactics or None, url))
        ids.add(o["id"]); stats["nodes"] += 1
    for o in objs:
        if o["type"] == "relationship" and o["source_ref"] in ids and o["target_ref"] in ids:
            db.execute("INSERT OR IGNORE INTO kg_edges VALUES(?,?,?)", (o["source_ref"], o["relationship_type"], o["target_ref"]))
            stats["edges"] += 1
        if o["type"] == "x-mitre-data-component" and o.get("x_mitre_data_source_ref") in ids:
            db.execute("INSERT OR IGNORE INTO kg_edges VALUES(?,?,?)", (o["id"], "component-of", o["x_mitre_data_source_ref"]))
            stats["edges"] += 1
        if o["type"] == "x-mitre-analytic":
            for ref in o.get("x_mitre_log_source_references", []):
                dc = ref.get("x_mitre_data_component_ref")
                if dc in ids:
                    db.execute("INSERT OR IGNORE INTO kg_edges VALUES(?,?,?)", (o["id"], "uses-data-component", dc))
                    stats["edges"] += 1
        if o["type"] == "x-mitre-detection-strategy":
            for an in o.get("x_mitre_analytic_refs", []):
                if an in ids:
                    db.execute("INSERT OR IGNORE INTO kg_edges VALUES(?,?,?)", (o["id"], "has-analytic", an))
                    stats["edges"] += 1

    labels = rule_map.get("d3fend_labels", {})
    for rule, spec in rule_map["rules"].items():
        for tid in spec.get("attack", []):
            row = db.execute("SELECT name FROM kg_nodes WHERE external_id=? AND node_type='Technique'", (tid,)).fetchone()
            db.execute("INSERT OR REPLACE INTO rule_refs VALUES(?,?,?,?,?)",
                       (rule, "attack", tid, f"ATT&CK {tid} {row[0]}" if row else tid, 1 if row else 0))
            if not row:
                stats["unresolved_refs"].append(f"{rule}:{tid}")
        for did in spec.get("d3fend", []):
            known = did in labels
            db.execute("INSERT OR REPLACE INTO rule_refs VALUES(?,?,?,?,?)",
                       (rule, "d3fend", did, f"D3FEND {did} {labels.get(did, '')}".strip(), 1 if known else 0))
            if not known:
                stats["unresolved_refs"].append(f"{rule}:{did}")
    db.execute("INSERT OR REPLACE INTO kg_meta VALUES('attack_collection_version', ?)", (str(version),))
    db.commit(); db.close()
    stats["attack_collection_version"] = version
    return stats


def resolved_refs(kg_path: str, rule_id: str) -> list[str]:
    """References an explanation may cite for a rule: resolved ones only."""
    with sqlite3.connect(kg_path) as db:
        return [r[0] for r in db.execute(
            "SELECT label FROM rule_refs WHERE rule_id=? AND resolved=1 ORDER BY ref_kind, ref_id", (rule_id,))]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attack-stix", required=True, help="path to enterprise-attack.json")
    ap.add_argument("--rule-map", default=str(pathlib.Path(__file__).with_name("hannibal_rule_map.json")))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    stats = build(json.loads(pathlib.Path(a.attack_stix).read_text(encoding="utf-8")),
                  json.loads(pathlib.Path(a.rule_map).read_text()), a.out)
    print(json.dumps(stats, indent=2))
    return 0 if not stats["unresolved_refs"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
