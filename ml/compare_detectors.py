"""Offline detector comparison for the Scipio loop (study, compare, adapt).

Compares K-Means candidates (k = 4, 8, 12) against the two required
baselines - rules only and IsolationForest novelty detection - on a held-out,
labeled set, with grouped bootstrap confidence intervals.

Inputs (CSV):
  train-benign / calibrate-benign: the eight FEATURES columns
  heldout: FEATURES + is_malicious (0/1) + device_id + group_id + window_end_ms
           group_id = incident (malicious) or lineage/session (benign); windows
           in one group are resampled together, never individually.

Output: JSON report. Nothing here is deployed; a passing report is one input
to ml/shadow_gate.py, which is one input to a human release decision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score

from features import FEATURES
from train_kmeans import load_feature_matrix, score, train

EPISODE_GAP_MS = 10 * 60_000
DAY_MS = 86_400_000


# ----------------------------------------------------------------- detectors

def rules_only_scores(x: np.ndarray) -> np.ndarray:
    """Transparent baseline: count of simple raw-telemetry rules that fire."""
    col = {f: i for i, f in enumerate(FEATURES)}
    r1 = (x[:, col["unsigned_executable_starts"]] > 0) & (x[:, col["persistence_changes"]] > 0)
    r2 = (x[:, col["new_executable_hashes_30d"]] > 0) & (x[:, col["unique_remote_destinations"]] >= 5)
    r3 = x[:, col["os_denied_connection_attempts"]] >= 10
    r4 = x[:, col["max_process_lineage_depth"]] >= 6
    return (r1.astype(int) + r2 + r3 + r4).astype(float)


def kmeans_detector(train_x, cal_x, k):
    art = train(train_x, cal_x, k=k)
    def scorer(x):
        out = [score(art, row) for row in x]
        return (np.array([o["anomaly_ratio"] for o in out]),
                np.array([o["out_of_training_support"] for o in out]))
    return art["model_id"], scorer, 1.0


def iforest_detector(train_x, cal_x, quantile=0.995):
    model = IsolationForest(n_estimators=200, random_state=42).fit(np.log1p(train_x))
    s = lambda x: -model.score_samples(np.log1p(x))
    threshold = float(np.quantile(s(cal_x), quantile))  # benign-calibrated, like the K-Means thresholds
    return "iforest", (lambda x: (s(x), np.zeros(len(x), dtype=bool))), threshold


# ------------------------------------------------------------------- metrics

def alert_episodes(frame: pd.DataFrame, flagged: np.ndarray) -> int:
    """Consecutive flagged windows on one device within EPISODE_GAP_MS are ONE episode."""
    episodes = 0
    f = frame.assign(_flag=flagged).loc[lambda d: d["_flag"]].sort_values(["device_id", "window_end_ms"])
    for _, g in f.groupby("device_id"):
        t = g["window_end_ms"].to_numpy()
        episodes += 1 + int(np.sum(np.diff(t) > EPISODE_GAP_MS))
    return episodes


def metrics(frame: pd.DataFrame, s: np.ndarray, threshold: float) -> dict:
    y = frame["is_malicious"].to_numpy(dtype=int)
    flagged = s > threshold if threshold > 0 else s >= 1
    benign = frame[y == 0]
    device_days = max(1, benign.groupby(["device_id", benign["window_end_ms"] // DAY_MS]).ngroups)
    tp = int(np.sum(flagged & (y == 1)))
    fp = int(np.sum(flagged & (y == 0)))
    malicious_groups = frame.loc[y == 1, "group_id"].unique()
    detected_groups = frame.loc[(y == 1) & flagged, "group_id"].unique()
    return {
        "average_precision": float(average_precision_score(y, s)) if len(set(y)) == 2 else float("nan"),
        "precision_at_threshold": tp / (tp + fp) if tp + fp else 0.0,
        "window_recall_at_threshold": tp / max(1, int(np.sum(y == 1))),
        "incident_recall_at_threshold": len(detected_groups) / max(1, len(malicious_groups)),
        "false_positive_windows_per_1000_benign": 1000 * fp / max(1, int(np.sum(y == 0))),
        "false_alert_episodes_per_endpoint_day": alert_episodes(benign, flagged[y == 0]) / device_days,
    }


def grouped_bootstrap(frame: pd.DataFrame, s: np.ndarray, threshold: float, n: int = 200, seed: int = 7) -> dict:
    """Resample whole groups (incident / lineage), not overlapping 60-second windows."""
    rng = np.random.default_rng(seed)
    groups = frame["group_id"].unique()
    idx_by_group = {g: np.flatnonzero(frame["group_id"].to_numpy() == g) for g in groups}
    keys = ("average_precision", "incident_recall_at_threshold", "false_alert_episodes_per_endpoint_day")
    samples = {k: [] for k in keys}
    for _ in range(n):
        pick = rng.choice(groups, size=len(groups), replace=True)
        idx = np.concatenate([idx_by_group[g] for g in pick])
        sub = frame.iloc[idx].reset_index(drop=True)
        if sub["is_malicious"].nunique() < 2:
            continue
        # Re-key resampled groups so duplicates count as separate incidents.
        sub["group_id"] = np.repeat(np.arange(len(pick)), [len(idx_by_group[g]) for g in pick])
        m = metrics(sub, s[idx], threshold)
        for k in keys:
            samples[k].append(m[k])
    return {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if v else None
            for k, v in samples.items()}


def compare(train_x: np.ndarray, cal_x: np.ndarray, heldout: pd.DataFrame, ks=(4, 8, 12),
            bootstrap: int = 200) -> dict:
    required = set(FEATURES) | {"is_malicious", "device_id", "group_id", "window_end_ms"}
    missing = required - set(heldout.columns)
    if missing:
        raise ValueError(f"Held-out set is missing columns: {sorted(missing)}")
    if heldout["is_malicious"].nunique() < 2:
        raise ValueError("Held-out set needs both benign and malicious windows")
    x = heldout[FEATURES].to_numpy(dtype=float)
    if not np.isfinite(x).all() or (x < 0).any():
        raise ValueError("Held-out features must be finite and nonnegative")

    detectors = [("rules_only", "rules", lambda z: (rules_only_scores(z), np.zeros(len(z), bool)), 0.0)]
    for k in ks:
        mid, f, thr = kmeans_detector(train_x, cal_x, k)
        detectors.append((f"kmeans_k{k}", mid, f, thr))
    detectors.append(("isolation_forest",) + iforest_detector(train_x, cal_x))

    results = {}
    for name, model_id, fn, thr in detectors:
        s, oos = fn(x)
        m = metrics(heldout, s, thr)
        m["out_of_support_fraction"] = float(np.mean(oos))
        m["model_id"] = model_id
        m["ci95_grouped_bootstrap"] = grouped_bootstrap(heldout, s, thr, n=bootstrap)
        results[name] = m

    digest = hashlib.sha256(pd.util.hash_pandas_object(heldout, index=False).values.tobytes()).hexdigest()
    return {
        "heldout_sha256": digest,
        "heldout_windows": int(len(heldout)),
        "heldout_groups": int(heldout["group_id"].nunique()),
        "detectors": results,
        "limits": ("Offline, held-out, window-level and incident-level metrics on the supplied data only. "
                   "Not a measurement of real-world protection. Severity and confidence remain uncalibrated "
                   "until a calibration study on representative endpoints is signed off."),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train-benign", required=True)
    ap.add_argument("--calibrate-benign", required=True)
    ap.add_argument("--heldout", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--bootstrap", type=int, default=200)
    a = ap.parse_args()
    report = compare(load_feature_matrix(a.train_benign), load_feature_matrix(a.calibrate_benign),
                     pd.read_csv(a.heldout), bootstrap=a.bootstrap)
    pathlib.Path(a.out).write_text(json.dumps(report, indent=2) + "\n")
    print("Offline comparison written (not a deployment decision):", a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
