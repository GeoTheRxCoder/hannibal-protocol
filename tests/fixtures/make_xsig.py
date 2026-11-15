"""Regenerates tests/fixtures/xsig: bundles signed by the PYTHON tool that the
C# verifier must accept (tests/Hannibal.Core.Tests, section "Cross-language").
Only public material is kept; the throwaway private key is discarded."""
import json, pathlib, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import hannibal_sign as hs

out = pathlib.Path(__file__).with_name("xsig")
out.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as tmp:
    a_key, a_pub = hs.keygen(tmp, "a")
    b_key, b_pub = hs.keygen(tmp, "b")
    (out / "trust-root-1of1.json").write_text(json.dumps(hs.trust_root([str(a_pub)], 1), indent=2) + "\n")
    (out / "trust-root-2of2.json").write_text(json.dumps(hs.trust_root([str(a_pub), str(b_pub)], 2), indent=2) + "\n")
    now = 1_900_000_000_000
    pol = hs.make_bundle("policy", "xsig-policy", 1, 30, {"mode": "simulation", "calibration_attested": False}, now_ms=now)
    (out / "policy.json").write_bytes(pol)
    (out / "policy.json.sig").write_text(json.dumps({"signatures": [hs.sign(str(a_key), pol)]}, indent=2) + "\n")
    (out / "policy-cosigned.json.sig").write_text(json.dumps({"signatures": [hs.sign(str(a_key), pol), hs.sign(str(b_key), pol)]}, indent=2) + "\n")
print("fixtures written to", out)
