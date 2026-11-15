import sys
import pathlib
import numpy as np
import pandas as pd
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"ml"))
from features import FEATURES
from train_kmeans import train,score
from evaluate_kmeans import evaluate

def test_heldout_evaluation_and_clip_disclosure():
    rng=np.random.default_rng(43)
    base=np.array([4,2,6,1,.2,.1,.2,.3])
    artifact=train(rng.poisson(base,size=(500,len(FEATURES))).astype(float),
                   rng.poisson(base,size=(400,len(FEATURES))).astype(float),k=4)
    benign=rng.poisson(base,size=(100,len(FEATURES))).astype(float)
    synthetic_attack=rng.poisson(base*6,size=(30,len(FEATURES))).astype(float)
    allrows=np.vstack([benign,synthetic_attack])
    df=pd.DataFrame(allrows,columns=FEATURES)
    df["is_malicious"]=[0]*100+[1]*30
    report=evaluate(artifact,df)
    assert report["evaluation_count"]==130
    assert 0<=report["average_precision"]<=1
    assert report["false_positives_per_1000_benign_windows"]>=0
    assert score(artifact,np.full(len(FEATURES),100000))["out_of_training_support"]
