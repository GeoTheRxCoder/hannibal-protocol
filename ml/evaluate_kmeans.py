"""Evaluate offline *held-out*, labeled endpoint windows, not training data.

False alerts per device-day cannot be inferred without real telemetry coverage
and deduplicated incident episodes; report them in deployment test harness.
"""
from __future__ import annotations
import json
from pathlib import Path
import argparse
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_fscore_support
from features import FEATURES
from train_kmeans import score

def evaluate(artifact: dict, heldout: pd.DataFrame) -> dict:
    required = set(FEATURES) | {"is_malicious"}
    if not required.issubset(heldout):
        raise ValueError(f"Missing columns: {sorted(required-set(heldout))}")
    if not set(heldout["is_malicious"].unique()).issubset({0,1}):
        raise ValueError("is_malicious must be 0 or 1")
    if heldout.empty or len(heldout["is_malicious"].unique()) < 2:
        raise ValueError("Evaluation requires both benign and malicious observations")
    answers=[]
    for row in heldout.itertuples(index=False):
        raw = np.array([getattr(row, f) for f in FEATURES], dtype=float)
        answers.append(score(artifact, raw))
    scorable=[s is not None for s in answers]
    y_true=heldout["is_malicious"].to_numpy(dtype=int)
    if not all(scorable):
        raise ValueError("Benchmark has unscorable inputs; report missingness separately")
    ratios=np.array([s["anomaly_ratio"] for s in answers])
    flagged=(ratios > 1).astype(int)
    p,r,f,_=precision_recall_fscore_support(
        y_true, flagged, average="binary", zero_division=0)
    fp=int(((y_true==0)&(flagged==1)).sum())
    tn=int((y_true==0).sum())
    return {
        "evaluation_count":len(y_true),
        "benign_count":tn,
        "malicious_count":int((y_true==1).sum()),
        "average_precision":float(average_precision_score(y_true,ratios)),
        "precision_at_candidate_threshold":float(p),
        "recall_at_candidate_threshold":float(r),
        "f1_at_candidate_threshold":float(f),
        "false_positives_at_candidate_threshold":fp,
        "false_positives_per_1000_benign_windows":float(1000*fp/tn),
        "out_of_support_fraction":float(np.mean(
            [s["out_of_training_support"] for s in answers])),
        "limits":"Offline window-level metrics; not measured real-world AV protection"
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--candidate",required=True)
    parser.add_argument("--heldout",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    artifact=json.loads(Path(args.candidate).read_text())
    if not artifact.get("is_candidate_only"):
        raise ValueError("Only untrusted candidate evaluation artifacts are accepted")
    result=evaluate(artifact,pd.read_csv(args.heldout))
    Path(args.output).write_text(json.dumps(result,indent=2)+"\n")
    print("Offline evaluation only:",args.output)
if __name__=="__main__":
    main()
