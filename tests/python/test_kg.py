import json, pathlib
from kg.build_attack_kg import build, resolved_refs

STIX = {"type": "bundle", "objects": [
    {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "18.1"},
    {"type": "x-mitre-tactic", "id": "x-mitre-tactic--imp", "name": "Impact",
     "external_references": [{"source_name": "mitre-attack", "external_id": "TA0040"}]},
    {"type": "attack-pattern", "id": "attack-pattern--enc", "name": "Data Encrypted for Impact",
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "impact"}],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1486", "url": "https://attack.mitre.org/techniques/T1486"}]},
    {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Old", "revoked": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1083"}]},
    {"type": "course-of-action", "id": "course-of-action--bk", "name": "Data Backup",
     "external_references": [{"source_name": "mitre-attack", "external_id": "M1053"}]},
    {"type": "relationship", "id": "relationship--1", "relationship_type": "mitigates",
     "source_ref": "course-of-action--bk", "target_ref": "attack-pattern--enc"},
    {"type": "x-mitre-data-component", "id": "x-mitre-data-component--fm", "name": "File Modification"},
    {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a1", "name": "Mass file modification",
     "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "x-mitre-data-component--fm"}]},
    {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--d1", "name": "Detect encryption",
     "x_mitre_analytic_refs": ["x-mitre-analytic--a1"]},
]}
RULES = {"rules": {"R-CANARY": {"attack": ["T1486", "T1083"], "d3fend": ["D3-DF", "D3-XYZ"]}},
         "d3fend_labels": {"D3-DF": "Decoy File"}}

def test_kg_build_resolves_only_real_references(tmp_path):
    out = tmp_path / "kg.db"
    stats = build(STIX, RULES, str(out))
    assert stats["attack_collection_version"] == "18.1"
    assert sorted(stats["unresolved_refs"]) == ["R-CANARY:D3-XYZ", "R-CANARY:T1083"]  # revoked T1083 is not resolvable
    refs = resolved_refs(str(out), "R-CANARY")
    assert refs == ["ATT&CK T1486 Data Encrypted for Impact", "D3FEND D3-DF Decoy File"]

def test_shipped_rule_map_is_well_formed():
    m = json.loads((pathlib.Path(__file__).resolve().parents[2] / "kg" / "hannibal_rule_map.json").read_text())
    assert {"R-CANARY", "R-INDICATOR", "R-PERSIST-UNTRUSTED", "R-LINEAGE-EGRESS", "R-ML-ANOMALY", "R-GRAPH-PATH"} <= set(m["rules"])
    assert not m["rules"]["R-ML-ANOMALY"]["attack"], "a ranking signal must not claim a technique"
