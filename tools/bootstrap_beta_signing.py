#!/usr/bin/env python3
"""One-step beta signing setup, run on YOUR machine (never on an endpoint).

Creates a release key, the pinned trust root, and the two bundles the beta
needs:
  - policy:      mode "simulation", calibration NOT attested (so network
                 blocks are never proposed, even as simulations)
  - indicators:  the EICAR anti-malware test-file hash only

Outputs:
  <out>/keys/      private key  -> keep offline, back it up, never ship it
  deploy/trust/trust-root.json  -> compiled into the services' install dir
  <out>/bundles/   policy.json(.sig), indicators.json(.sig) -> copy to
                   %ProgramData%\\Hannibal\\bundles on the test machine
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hannibal_sign as hs  # noqa: E402
from build_indicator_payload import EICAR_SHA256  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="signing-workspace")
    ap.add_argument("--days", type=float, default=30)
    ap.add_argument("--trust-out", default=str(HERE.parent / "deploy" / "trust" / "trust-root.json"))
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    kp, pp = hs.keygen(str(out / "keys"), "release-1")
    root = hs.trust_root([str(pp)], 1)
    trust_file = pathlib.Path(a.trust_out)
    trust_file.parent.mkdir(parents=True, exist_ok=True)
    trust_file.write_text(json.dumps(root, indent=2) + "\n")

    bdir = out / "bundles"
    bdir.mkdir(parents=True, exist_ok=True)
    bundles = {
        "policy": {"mode": "simulation", "calibration_attested": False},
        "indicators": {"indicators": [{"indicator_id": "eicar-test-file", "sha256": EICAR_SHA256,
                                       "source": "EICAR anti-malware test file"}], "revoked": []},
    }
    for btype, payload in bundles.items():
        data = hs.make_bundle(btype, f"beta-{btype}", 1, a.days, payload)
        (bdir / f"{btype}.json").write_bytes(data)
        (bdir / f"{btype}.json.sig").write_text(json.dumps({"signatures": [hs.sign(str(kp), data)]}, indent=2) + "\n")
        assert hs.verify(root, data, json.loads((bdir / f"{btype}.json.sig").read_text()), btype) == "None"
    print(f"Private key (keep offline): {kp}")
    print(f"Trust root:                 {trust_file}")
    print(f"Signed bundles:             {bdir}")
    print(f"Bundles expire in {a.days:g} days; re-sign with a higher --version before then.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
