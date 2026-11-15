#!/usr/bin/env python3
"""Render a status snapshot as a static HTML preview of the WPF dashboard.

For design review on machines without Windows. Mirrors the layout, palette,
type and status-chip rules of src/Hannibal.Desktop (brand guide v1.0). The WPF
app remains the product; this preview is read-only and offline.

  python tools/render_snapshot_preview.py drill-out/snapshot.json preview.html
"""
from __future__ import annotations

import base64
import html
import json
import pathlib
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
FONTS = ROOT / "src" / "Hannibal.Desktop" / "Fonts"
LOGO = ROOT / "src" / "Hannibal.Desktop" / "Assets" / "maneuver-reversed.png"

LEVEL = {"healthy": "Healthy", "watched": "Healthy", "resolved": "Healthy", "rolled_back": "Healthy", "contained": "High", "degraded": "Review", "review": "Review",
         "unwatched": "Review", "investigating": "Review", "open": "Review", "failed": "Review",
         "expired": "Review", "high": "High", "offline": "High", "tripped": "High"}
GLYPH = {"Healthy": "●", "Review": "▲", "High": "■", "Info": "◆"}
COLOR = {"Healthy": "#B5E881", "Review": "#D9B48A", "High": "#E89A6E", "Info": "#74C0DE"}


def e(x) -> str:
    return html.escape("" if x is None else str(x))


def chip(state: str) -> str:
    level = LEVEL.get((state or "").lower(), "Info")
    raw = (state or "").replace("_", " ").lower()
    label = level if raw in ("", level.lower()) else f"{level} / {raw}"
    return f'<span class="chip" style="color:{COLOR[level]}"><span aria-hidden="true">{GLYPH[level]}</span> {e(label)}</span>'


def when(ms) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ms else "—"


def font_face(family: str, file: str, weight: int) -> str:
    p = FONTS / file
    if not p.exists():
        return ""
    data = base64.b64encode(p.read_bytes()).decode()
    return f"@font-face{{font-family:'{family}';src:url(data:font/ttf;base64,{data}) format('truetype');font-weight:{weight};}}"


def render(s: dict) -> str:
    faces = "".join([font_face("DM Sans", "DMSans-Regular.ttf", 400), font_face("DM Sans", "DMSans-Medium.ttf", 500),
                     font_face("DM Sans", "DMSans-Bold.ttf", 700), font_face("IBM Plex Mono", "IBMPlexMono-Regular.ttf", 400),
                     font_face("IBM Plex Mono", "IBMPlexMono-Medium.ttf", 500)])
    logo = f'<img src="data:image/png;base64,{base64.b64encode(LOGO.read_bytes()).decode()}" alt="Hannibal Protocol symbol">' if LOGO.exists() else ""

    def rows(items, name, state, detail=None):
        out = []
        for it in items:
            d = f'<div class="quiet small">{e(it[detail])}</div>' if detail else ""
            out.append(f'<div class="row"><div class="rowhead"><span class="name">{e(it[name])}</span>{chip(it[state])}</div>{d}</div>')
        return "".join(out)

    incidents = []
    for i in s["incidents"]:
        claims = "".join(
            f'<div class="claim"><div>{e(c["text"])}</div>'
            f'<div class="label">EVIDENCE ROOTS&nbsp; {e("  ".join(c["rootEventIds"]))}</div>'
            + (f'<div class="label">REFERENCE&nbsp; {e("  ".join(c["references"]))}</div>' if c["references"] else "")
            + "</div>" for c in i["claims"])
        actions = "".join(
            f'<div class="action"><div class="rowhead"><span class="label lime">SIMULATED ACTION&nbsp; {e(a["type"])}</span>{chip(a["state"])}</div>'
            f'<div class="quiet">No change was made to this device.</div>'
            f'<div class="label">TTL EXPIRES&nbsp; {e(when(a["expiresMs"]))}</div>'
            + (f'<div class="label">ROLLBACK TOKEN&nbsp; {e(a["rollbackToken"])}</div>' if a["rollbackToken"] else "")
            + "</div>" for a in i["actions"])
        incidents.append(f'''<div class="card">
          <div class="rowhead"><span class="label paper">{e(i["label"])}</span>{chip(i["status"])}</div>
          <div class="sentence">{e(i["sentence"])}</div>
          <div class="label">DECISION {e(i["decisionKind"])}&nbsp; / &nbsp;{e(i["reasonCode"])}</div>
          <div class="label">TARGET {e(i["targetKind"])}&nbsp; {e(i["targetKey"])}</div>
          <div class="label">LADDER RUNG {e(i["rung"])}&nbsp; / &nbsp;EXPIRES {e(when(i["rungExpiresMs"]))}</div>
          <div class="label" style="margin-bottom:8px">ORDERING HEURISTIC (UNCALIBRATED)&nbsp; severity {i["severity"]:.2f}&nbsp; confidence {i["confidence"]:.2f}</div>
          {claims}{actions}</div>''')

    notices = "".join(f"<div>{e(n)}</div>" for n in s["notices"])
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Hannibal Protocol — dashboard preview</title><style>
{faces}
*{{box-sizing:border-box}} body{{margin:0;background:#111510;color:#DCE4D5;font:14px/1.5 'DM Sans',system-ui,sans-serif}}
.header{{display:flex;justify-content:space-between;align-items:center;padding:12px 24px;border-bottom:1px solid #2F392D}}
.brand{{display:flex;align-items:center;gap:12px;font-weight:700;color:#F1EEE6}} .brand img{{height:40px}}
.env{{text-align:right}} .label{{font:12px/1.5 'IBM Plex Mono',Consolas,monospace;color:#A9B3A3;word-break:break-all}}
.lime{{color:#B5E881}} .paper{{color:#F1EEE6}} .olive{{color:#858C35}}
main{{padding:24px;max-width:1400px}} h1{{font-size:32px;line-height:40px;margin:0;color:#F1EEE6}}
h2{{font-size:16px;font-weight:500;color:#F1EEE6;margin:0 0 8px}} .quiet{{color:#A9B3A3}} .small{{font-size:12px;line-height:18px}}
.figs{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:24px}}
.card{{background:#1F271E;border:1px solid #2F392D;border-radius:6px;padding:16px;margin-bottom:16px}}
.fig{{font-size:32px;line-height:40px;font-weight:700;color:#F1EEE6}}
.grid{{display:grid;grid-template-columns:3fr 2fr;gap:24px}}
.rowhead{{display:flex;justify-content:space-between;gap:8px;align-items:baseline}} .row{{margin-bottom:8px}} .name{{color:#F1EEE6}}
.chip{{font:12px 'IBM Plex Mono',Consolas,monospace;white-space:nowrap}}
.sentence{{font-size:16px;color:#F1EEE6;margin:8px 0}} .claim{{border-top:1px solid #2F392D;padding:8px 0}}
.action{{border:1px solid #858C35;border-radius:6px;padding:8px;margin-top:8px}}
.footer{{display:flex;justify-content:space-between;background:#242622;padding:8px 24px}}
</style></head><body>
<div class="header"><div class="brand">{logo}<span>HANNIBAL PROTOCOL</span></div>
<div class="env"><div class="label lime">{e(s["environment"])}</div><div class="label">{e(s["scope"])}</div></div></div>
<main><h1>Security overview</h1><div class="quiet" style="margin-top:8px">Seven agents. One coordinated defense.</div>
<div class="figs">
<div class="card"><div class="quiet">Devices in scope</div><div class="fig">{s["devicesInScope"]:02d}</div></div>
<div class="card"><div class="quiet">Investigations</div><div class="fig">{s["openInvestigations"]:02d}</div></div>
<div class="card"><div class="quiet">Agents healthy</div><div class="fig">{s["agentsHealthy"]} / {s["agentsTotal"]}</div></div></div>
<div class="card">{chip("Info")}<div style="margin-top:8px">{notices}</div></div>
<div class="grid"><div><h2>Investigations</h2>{"".join(incidents) or '<div class="quiet">No investigations are open.</div>'}</div>
<div><h2>Agents</h2><div class="card">{rows(s["agents"], "name", "health", "detail")}</div>
<h2>Trust gates</h2><div class="card">{rows(s["trustGates"], "name", "status", "detail")}</div>
<h2>Approach axes</h2><div class="card">{"".join(f'<div class="rowhead row"><span class="label" style="color:#DCE4D5">{e(a["axis"])}</span>{chip(a["status"])}</div>' for a in s["axes"])}</div>
<h2>Recursive learning</h2><div class="card"><div class="label olive" style="margin-bottom:8px">CURATE / EVALUATE / SHADOW / REVIEW</div>{rows(s["relay"], "stage", "status", "detail")}</div>
<h2>Record</h2><div class="card"><div class="label">DECOYS&nbsp; {s["decoysDeployed"]} deployed / {s["decoysTripped"]} touched</div>
<div class="label">AUDIT ENTRIES&nbsp; {s["auditEntries"]} / CHAIN INTACT {s["auditIntact"]}</div><div class="label">HEAD&nbsp; {e(s["auditHead"])}</div></div>
</div></div></main>
<div class="footer"><span class="label">Preview rendered from a snapshot file. Saved drill snapshots are not live status.</span><span class="label">SNAPSHOT {e(when(s["generatedMs"]))}</span></div>
</body></html>"""


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__); return 2
    snap = json.loads(pathlib.Path(sys.argv[1]).read_text())
    pathlib.Path(sys.argv[2]).write_text(render(snap), encoding="utf-8")
    print("Preview written:", sys.argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
