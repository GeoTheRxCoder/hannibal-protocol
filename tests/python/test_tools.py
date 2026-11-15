import json, subprocess, sys
import pytest
import hannibal_sign as hs
from build_indicator_payload import build, EICAR_SHA256

NOW = 1_900_000_000_000

def test_sign_and_verify_round_trip(tmp_path):
    k, p = hs.keygen(tmp_path, "k")
    root = hs.trust_root([str(p)], 1)
    b = hs.make_bundle("policy", "p", 1, 1, {"mode": "simulation"}, now_ms=NOW)
    sig = {"signatures": [hs.sign(str(k), b)]}
    assert hs.verify(root, b, sig, "policy", now_ms=NOW) == "None"
    assert hs.verify(root, b.replace(b"simulation", b"enforcing!"), sig, "policy", now_ms=NOW) == "UnknownKeyOrBadSignature"
    assert hs.verify(root, b, sig, "indicators", now_ms=NOW) == "TypeMismatch"
    assert hs.verify(root, b, sig, "policy", now_ms=NOW + 2 * 86_400_000) == "Expired"

def test_threshold_requires_distinct_keys(tmp_path):
    k1, p1 = hs.keygen(tmp_path, "a"); k2, p2 = hs.keygen(tmp_path, "b")
    root = hs.trust_root([str(p1), str(p2)], 2)
    b = hs.make_bundle("indicators", "i", 1, 1, {"indicators": []}, now_ms=NOW)
    assert hs.verify(root, b, {"signatures": [hs.sign(str(k1), b), hs.sign(str(k1), b)]}, "indicators", now_ms=NOW) == "ThresholdNotMet"
    assert hs.verify(root, b, {"signatures": [hs.sign(str(k1), b), hs.sign(str(k2), b)]}, "indicators", now_ms=NOW) == "None"

def test_keygen_refuses_to_overwrite(tmp_path):
    hs.keygen(tmp_path, "k")
    with pytest.raises(SystemExit):
        hs.keygen(tmp_path, "k")

def test_indicator_payload_filters_known_good_and_invalid():
    good = "a" * 64
    rows = [{"indicator_id": "x", "sha256": EICAR_SHA256.upper()}, {"indicator_id": "y", "sha256": good},
            {"indicator_id": "z", "sha256": "not-a-hash"}, {"indicator_id": "w", "sha256": EICAR_SHA256}]
    payload, report = build(rows, {good}, {"old-1"}, NOW)
    assert [i["sha256"] for i in payload["indicators"]] == [EICAR_SHA256]
    assert report == {"input": 4, "invalid": 1, "known_good_dropped": 1, "duplicates": 1, "kept": 1}
    assert payload["revoked"] == ["old-1"]

def test_bootstrap_writes_verifiable_bundles(tmp_path):
    trust = tmp_path / "trust-root.json"
    subprocess.run([sys.executable, "tools/bootstrap_beta_signing.py", "--out", str(tmp_path / "ws"),
                    "--trust-out", str(trust)], check=True, capture_output=True)
    root = json.loads(trust.read_text())
    for t in ("policy", "indicators"):
        b = (tmp_path / "ws" / "bundles" / f"{t}.json").read_bytes()
        sig = json.loads((tmp_path / "ws" / "bundles" / f"{t}.json.sig").read_text())
        assert hs.verify(root, b, sig, t) == "None"
    pol = json.loads((tmp_path / "ws" / "bundles" / "policy.json").read_text())
    assert pol["payload"] == {"mode": "simulation", "calibration_attested": False}
