"""Shadow-mode promotion gate (the Relay: curate -> evaluate -> shadow -> review).

Decides whether a candidate model may be PROPOSED for a signed release. It
never activates, signs or deploys anything, and a "pass" still needs a human
reviewer and the independent release pipeline.

Inputs:
  --incumbent / --candidate : detector entries from ml/compare_detectors.py
                              (same held-out set; the digests must match)
  --shadow                  : JSON summary of the candidate's shadow period:
                              {"days": 21, "endpoints": 40,
                               "false_alert_episodes_per_endpoint_week": 0.6,
                               "drift_out_of_support_fraction": 0.004,
                               "poisoning_review_passed": true}
"""
from __future__ import annotations

import argparse
import json
import pathlib

GATES = {
    "min_shadow_days": 14,
    "min_shadow_endpoints": 10,
    "max_false_alert_episodes_per_endpoint_week": 1.0,
    "min_average_precision_gain": 0.01,
    "max_incident_recall_regression": 0.02,
    "max_out_of_support_fraction": 0.02,
}


def decide(incumbent: dict, candidate: dict, shadow: dict, same_heldout: bool, gates: dict = GATES) -> dict:
    reasons = []
    if not same_heldout:
        reasons.append("Candidate and incumbent were not evaluated on the same held-out set")
    if shadow.get("days", 0) < gates["min_shadow_days"]:
        reasons.append(f"Shadow period {shadow.get('days', 0)} d < {gates['min_shadow_days']} d")
    if shadow.get("endpoints", 0) < gates["min_shadow_endpoints"]:
        reasons.append(f"Shadow cohort {shadow.get('endpoints', 0)} endpoints < {gates['min_shadow_endpoints']}")
    fae = shadow.get("false_alert_episodes_per_endpoint_week")
    if fae is None or fae > gates["max_false_alert_episodes_per_endpoint_week"]:
        reasons.append(f"False alert episodes per endpoint-week {fae} exceeds {gates['max_false_alert_episodes_per_endpoint_week']}")
    if not shadow.get("poisoning_review_passed", False):
        reasons.append("Training-data poisoning review not recorded as passed")
    oos = shadow.get("drift_out_of_support_fraction", 1.0)
    if oos > gates["max_out_of_support_fraction"]:
        reasons.append(f"Out-of-support fraction {oos} exceeds {gates['max_out_of_support_fraction']}")
    gain = candidate["average_precision"] - incumbent["average_precision"]
    if gain < gates["min_average_precision_gain"]:
        reasons.append(f"Average-precision gain {gain:.4f} below {gates['min_average_precision_gain']}")
    regression = incumbent["incident_recall_at_threshold"] - candidate["incident_recall_at_threshold"]
    if regression > gates["max_incident_recall_regression"]:
        reasons.append(f"Incident recall regresses by {regression:.4f}")
    # The lower CI bound must not fall below the incumbent's point estimate by more than the tolerance.
    ci = (candidate.get("ci95_grouped_bootstrap") or {}).get("incident_recall_at_threshold")
    if ci and incumbent["incident_recall_at_threshold"] - ci[0] > gates["max_incident_recall_regression"] * 3:
        reasons.append("Incident-recall confidence interval is too wide to rule out a material regression")
    return {
        "decision": "propose_for_review" if not reasons else "reject",
        "reasons": reasons,
        "average_precision_gain": gain,
        "gates": gates,
        "note": "A proposal is not an activation. Signing and staged rollout happen in the release pipeline.",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", required=True, help="output of compare_detectors.py")
    ap.add_argument("--incumbent", required=True, help="detector name in the report, e.g. rules_only")
    ap.add_argument("--candidate", required=True, help="detector name in the report, e.g. kmeans_k8")
    ap.add_argument("--shadow", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    report = json.loads(pathlib.Path(a.report).read_text())
    d = report["detectors"]
    result = decide(d[a.incumbent], d[a.candidate], json.loads(pathlib.Path(a.shadow).read_text()), True)
    result.update({"incumbent": a.incumbent, "candidate": a.candidate, "heldout_sha256": report["heldout_sha256"]})
    pathlib.Path(a.out).write_text(json.dumps(result, indent=2) + "\n")
    print(result["decision"], *result["reasons"], sep="\n  ")
    return 0 if result["decision"] == "propose_for_review" else 2


if __name__ == "__main__":
    raise SystemExit(main())
