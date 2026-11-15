import pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "ml", ROOT / "tools"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
