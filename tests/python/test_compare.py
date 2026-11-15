import numpy as np
import pandas as pd
from features import FEATURES
from compare_detectors import compare, alert_episodes
from shadow_gate import decide

rng = np.random.default_rng(3)

def benign(n):
    return np.column_stack([rng.poisson(2, n), rng.poisson(3, n), rng.poisson(6, n), rng.binomial(1, .02, n),
                            rng.binomial(1, .01, n), rng.poisson(.2, n), rng.integers(1, 4, n), rng.binomial(1, .05, n)]).astype(float)

def malicious(n):
    return np.column_stack([rng.poisson(15, n), rng.poisson(25, n), rng.poisson(60, n), rng.poisson(3, n),
                            rng.poisson(2, n), rng.poisson(12, n), rng.integers(5, 9, n), rng.poisson(4, n)]).astype(float)

def heldout():
    rows = []
    for d in range(6):
        for g in range(8):
            x = benign(5)
            for i, r in enumerate(x):
                rows.append([*r, 0, f"dev{d}", f"b{d}-{g}", d * 86_400_000 + g * 3_600_000 + i * 60_000])
    for g in range(10):
        for i, r in enumerate(malicious(4)):
            rows.append([*r, 1, f"dev{g % 6}", f"m{g}", g * 7_200_000 + i * 60_000])
    return pd.DataFrame(rows, columns=FEATURES + ["is_malicious", "device_id", "group_id", "window_end_ms"])

def test_compare_reports_all_required_detectors():
    report = compare(benign(600), benign(400), heldout(), bootstrap=30)
    names = set(report["detectors"])
    assert {"rules_only", "kmeans_k4", "kmeans_k8", "kmeans_k12", "isolation_forest"} <= names
    for m in report["detectors"].values():
        assert 0 <= m["average_precision"] <= 1
        assert m["ci95_grouped_bootstrap"]["incident_recall_at_threshold"] is not None
    # On cleanly separated synthetic data every learned detector should find every incident.
    assert report["detectors"]["kmeans_k8"]["incident_recall_at_threshold"] == 1.0
    assert "Not a measurement of real-world protection" in report["limits"]

def test_alert_episodes_merge_adjacent_windows():
    f = pd.DataFrame({"device_id": ["a"] * 4 + ["b"], "window_end_ms": [0, 60_000, 120_000, 3_600_000, 0]})
    assert alert_episodes(f, np.array([True, True, True, True, True])) == 3

def test_shadow_gate_rejects_short_shadow_and_regressions():
    inc = {"average_precision": .70, "incident_recall_at_threshold": .90}
    good = {"average_precision": .75, "incident_recall_at_threshold": .90,
            "ci95_grouped_bootstrap": {"incident_recall_at_threshold": [.86, .94]}}
    shadow = {"days": 21, "endpoints": 25, "false_alert_episodes_per_endpoint_week": .5,
              "drift_out_of_support_fraction": .001, "poisoning_review_passed": True}
    assert decide(inc, good, shadow, True)["decision"] == "propose_for_review"
    assert decide(inc, good, shadow | {"days": 5}, True)["decision"] == "reject"
    assert decide(inc, good, shadow | {"poisoning_review_passed": False}, True)["decision"] == "reject"
    assert decide(inc, good | {"incident_recall_at_threshold": .80}, shadow, True)["decision"] == "reject"
    assert decide(inc, good, shadow, False)["decision"] == "reject"
