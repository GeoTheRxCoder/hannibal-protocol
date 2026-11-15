"""Train an OFFLINE candidate K-Means artifact; never auto-deploy.

Inputs are separately curated BENIGN windows in CSVs with columns listed in
features.FEATURES. No input samples/labels/files are included in the artifact.
Production must sign the artifact and validate it prior to local activation.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import hashlib
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from features import FEATURES, FEATURE_SCHEMA

def load_feature_matrix(path: str) -> np.ndarray:
    frame = pd.read_csv(path)
    missing = set(FEATURES) - set(frame.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")
    values = frame[FEATURES].to_numpy(dtype=float)
    if values.ndim != 2 or values.shape[0] == 0:
        raise ValueError("Empty feature matrix")
    if not np.isfinite(values).all() or (values < 0).any():
        raise ValueError("All feature counts must be finite and nonnegative")
    return values

def train(train_raw: np.ndarray, calibration_raw: np.ndarray,
          k: int = 8, quantile: float = 0.995) -> dict:
    if train_raw.shape[1] != len(FEATURES) or calibration_raw.shape[1] != len(FEATURES):
        raise ValueError("Wrong feature vector width")
    if len(train_raw) < max(200, k * 20) or len(calibration_raw) < max(100, k * 20):
        raise ValueError("Insufficient train/calibration examples for candidate")
    if not 0.95 <= quantile < 1:
        raise ValueError("Quantile must be in [0.95, 1)")
    if (not np.isfinite(train_raw).all() or not np.isfinite(calibration_raw).all()
        or (train_raw < 0).any() or (calibration_raw < 0).any()):
        raise ValueError("Training features must be finite and nonnegative")
    caps = np.quantile(train_raw, .995, axis=0)
    def transform(raw: np.ndarray) -> np.ndarray:
        return np.log1p(np.minimum(np.maximum(raw, 0), caps))
    scaler = StandardScaler().fit(transform(train_raw))
    z_train = scaler.transform(transform(train_raw))
    model = KMeans(n_clusters=k, init="k-means++", n_init=20, random_state=42)
    model.fit(z_train)
    z_cal = scaler.transform(transform(calibration_raw))
    dist = np.linalg.norm(z_cal[:,None,:] - model.cluster_centers_[None,:,:], axis=2)
    nearest = np.argmin(dist, axis=1)
    nearest_d = dist[np.arange(len(dist)), nearest]
    global_cut = float(max(np.quantile(nearest_d, quantile), 1e-6))
    min_cluster = max(30, round(.03 * len(calibration_raw)))
    thresholds = []
    cluster_counts = []
    for ci in range(k):
        cluster_dist = nearest_d[nearest == ci]
        cluster_counts.append(int(len(cluster_dist)))
        cut = (float(np.quantile(cluster_dist, quantile))
               if len(cluster_dist) >= min_cluster else global_cut)
        thresholds.append(max(cut, 1e-6))
    artifact = {
        "artifact_schema": 1,
        "feature_schema": FEATURE_SCHEMA,
        "feature_names": FEATURES,
        "window_seconds": 60,
        "min_coverage": 0.90,
        "winsor_caps": caps.tolist(),
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "centroids": model.cluster_centers_.tolist(),
        "thresholds": thresholds,
        "calibration_quantile": quantile,
        "train_count": int(len(train_raw)),
        "calibration_count": int(len(calibration_raw)),
        "calibration_cluster_counts": cluster_counts,
        "is_candidate_only": True
    }
    canonical = json.dumps(artifact, sort_keys=True, separators=(",",":"), allow_nan=False)
    artifact["model_id"] = "km-" + hashlib.sha256(canonical.encode()).hexdigest()[:24]
    return artifact

def score(artifact: dict, raw: np.ndarray, coverage: float = 1.0):
    if coverage < artifact["min_coverage"]:
        return None
    raw = np.asarray(raw, dtype=float)
    if (raw.shape != (len(FEATURES),) or
        not np.isfinite(raw).all() or (raw < 0).any()):
        return None
    caps = np.asarray(artifact["winsor_caps"])
    mean = np.asarray(artifact["mean"])
    scale = np.asarray(artifact["scale"])
    exceeded = int(np.count_nonzero(raw > caps))
    z = (np.log1p(np.minimum(raw, caps)) - mean) / scale
    distances = np.linalg.norm(np.asarray(artifact["centroids"]) - z, axis=1)
    cluster = int(np.argmin(distances))
    threshold = float(artifact["thresholds"][cluster])
    return {"cluster":cluster, "distance":float(distances[cluster]),
            "threshold":threshold,
            "anomaly_ratio":float(distances[cluster]/threshold),
            "exceeded_training_caps":exceeded,
            "out_of_training_support": bool(exceeded > 0)}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--train-benign", required=True)
    parser.add_argument("--calibrate-benign", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--k", type=int, default=8)
    args=parser.parse_args()
    artifact=train(load_feature_matrix(args.train_benign),
                   load_feature_matrix(args.calibrate_benign), args.k)
    pathlib.Path(args.out).write_text(json.dumps(artifact, indent=2, allow_nan=False)+"\n")
    print("Candidate artifact written, NOT signed or deployable:", args.out)

if __name__ == "__main__":
    main()
