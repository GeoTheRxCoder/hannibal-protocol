import sys
import pathlib
import numpy as np

ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/"ml"))
from features import FEATURES
from train_kmeans import train, score

def test_training_and_safe_missingness():
    rng=np.random.default_rng(17)
    baseline=rng.poisson(lam=np.array([4,2,6,1,.2,.1,.2,.3]),
                         size=(700,len(FEATURES))).astype(float)
    calibration=rng.poisson(lam=np.array([4,2,6,1,.2,.1,.2,.3]),
                            size=(400,len(FEATURES))).astype(float)
    artifact=train(baseline,calibration,k=4)
    assert len(artifact["centroids"])==4
    assert score(artifact,baseline[0])["anomaly_ratio"] >= 0
    assert score(artifact,baseline[0],coverage=.4) is None
    assert score(artifact,np.full(len(FEATURES),np.nan)) is None
    assert score(artifact,np.full(len(FEATURES),-1.)) is None
