#!/usr/bin/env python3
"""Hannibal Protocol release signing tool (offline).

Creates ECDSA P-256 signing keys, the pinned trust root shipped with the
installer, and detached signatures over bundle files. The signature covers
the exact bytes of the bundle file; the C# verifier
(src/Hannibal.Core/Crypto/SignedBundle.cs) checks the same bytes, so no JSON
canonicalization is involved.

Run this on a signing workstation, not on an endpoint. Private keys never
belong in the repository, the installer, or ProgramData.

  keygen      --out-dir DIR [--name NAME]
  trust-root  --pub PUB.pem [--pub ...] --threshold N --out trust-root.json
  bundle      --type {policy,indicators,model} --id ID --version N
              --days D --payload payload.json --out bundle.json
  sign        --key KEY.pem --bundle bundle.json [--append]
  verify      --trust-root trust-root.json --bundle bundle.json --type T
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ALG = "ecdsa-p256-sha256"
BUNDLE_TYPES = ("policy", "indicators", "model")


def key_id(spki_der: bytes) -> str:
    return hashlib.sha256(spki_der).hexdigest()[:16]


def spki_of(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


def keygen(out_dir: str, name: str) -> tuple[pathlib.Path, pathlib.Path]:
    d = pathlib.Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    priv = ec.generate_private_key(ec.SECP256R1())
    kp, pp = d / f"{name}.key.pem", d / f"{name}.pub.pem"
    if kp.exists():
        raise SystemExit(f"Refusing to overwrite existing key {kp}")
    kp.write_bytes(priv.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    try:
        os.chmod(kp, 0o600)
    except OSError:
        pass
    pp.write_bytes(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return kp, pp


def trust_root(pub_paths: list[str], threshold: int) -> dict:
    keys = []
    for p in pub_paths:
        pub = serialization.load_pem_public_key(pathlib.Path(p).read_bytes())
        if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
            raise SystemExit(f"{p}: only ECDSA P-256 keys are supported")
        der = spki_of(pub)
        keys.append({"keyid": key_id(der), "alg": ALG, "spki_b64": base64.b64encode(der).decode()})
    if len({k["keyid"] for k in keys}) != len(keys):
        raise SystemExit("Duplicate key in trust root")
    if not 1 <= threshold <= len(keys):
        raise SystemExit("Threshold must be between 1 and the number of keys")
    return {"keys": keys, "threshold": threshold}


def make_bundle(btype: str, bid: str, version: int, days: float, payload: dict,
                now_ms: int | None = None) -> bytes:
    if btype not in BUNDLE_TYPES:
        raise SystemExit(f"Unknown bundle type {btype}")
    if version < 1 or not bid:
        raise SystemExit("Bundle id and a positive version are required")
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    doc = {"bundle_type": btype, "bundle_id": bid, "version": version,
           "issued_ms": now_ms, "expires_ms": now_ms + int(days * 86_400_000),
           "payload": payload}
    return (json.dumps(doc, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def sign(key_path: str, bundle_bytes: bytes) -> dict:
    priv = serialization.load_pem_private_key(pathlib.Path(key_path).read_bytes(), password=None)
    sig = priv.sign(bundle_bytes, ec.ECDSA(hashes.SHA256()))  # DER (RFC 3279) encoding
    return {"keyid": key_id(spki_of(priv.public_key())), "alg": ALG,
            "sig": base64.b64encode(sig).decode()}


def verify(root: dict, bundle_bytes: bytes, sig_doc: dict, expected_type: str,
           now_ms: int | None = None) -> str:
    """Mirror of SignedBundleVerifier.Verify (minus rollback state). Returns a failure code or 'None'."""
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    valid = set()
    keys = {k["keyid"]: k for k in root["keys"]}
    for s in sig_doc.get("signatures", []):
        k = keys.get(s.get("keyid"))
        if not k or k["alg"] != s.get("alg"):
            continue
        pub = serialization.load_der_public_key(base64.b64decode(k["spki_b64"]))
        try:
            pub.verify(base64.b64decode(s["sig"]), bundle_bytes, ec.ECDSA(hashes.SHA256()))
            valid.add(k["keyid"])
        except InvalidSignature:
            pass
    if not valid:
        return "UnknownKeyOrBadSignature"
    if len(valid) < root["threshold"]:
        return "ThresholdNotMet"
    doc = json.loads(bundle_bytes)
    if doc["bundle_type"] != expected_type:
        return "TypeMismatch"
    if now_ms >= doc["expires_ms"]:
        return "Expired"
    if now_ms < doc["issued_ms"] - 300_000:
        return "NotYetValid"
    return "None"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--out-dir", required=True); k.add_argument("--name", default="release-1")
    t = sub.add_parser("trust-root"); t.add_argument("--pub", action="append", required=True)
    t.add_argument("--threshold", type=int, default=1); t.add_argument("--out", required=True)
    b = sub.add_parser("bundle"); b.add_argument("--type", required=True, choices=BUNDLE_TYPES)
    b.add_argument("--id", required=True); b.add_argument("--version", type=int, required=True)
    b.add_argument("--days", type=float, default=30); b.add_argument("--payload", required=True)
    b.add_argument("--out", required=True)
    s = sub.add_parser("sign"); s.add_argument("--key", required=True); s.add_argument("--bundle", required=True)
    s.add_argument("--append", action="store_true", help="add a co-signature to an existing .sig")
    v = sub.add_parser("verify"); v.add_argument("--trust-root", required=True)
    v.add_argument("--bundle", required=True); v.add_argument("--type", required=True, choices=BUNDLE_TYPES)
    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        kp, pp = keygen(a.out_dir, a.name)
        print(f"Private key: {kp}  (keep offline)\nPublic key:  {pp}")
    elif a.cmd == "trust-root":
        pathlib.Path(a.out).write_text(json.dumps(trust_root(a.pub, a.threshold), indent=2) + "\n")
        print("Trust root written:", a.out)
    elif a.cmd == "bundle":
        payload = json.loads(pathlib.Path(a.payload).read_text())
        pathlib.Path(a.out).write_bytes(make_bundle(a.type, a.id, a.version, a.days, payload))
        print("Unsigned bundle written:", a.out)
    elif a.cmd == "sign":
        data = pathlib.Path(a.bundle).read_bytes()
        sig_path = pathlib.Path(a.bundle + ".sig")
        doc = json.loads(sig_path.read_text()) if a.append and sig_path.exists() else {"signatures": []}
        doc["signatures"].append(sign(a.key, data))
        sig_path.write_text(json.dumps(doc, indent=2) + "\n")
        print(f"Signature written: {sig_path} (sha256 {hashlib.sha256(data).hexdigest()})")
    elif a.cmd == "verify":
        root = json.loads(pathlib.Path(a.trust_root).read_text())
        data = pathlib.Path(a.bundle).read_bytes()
        result = verify(root, data, json.loads(pathlib.Path(a.bundle + ".sig").read_text()), a.type)
        print("Verification:", result)
        return 0 if result == "None" else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
