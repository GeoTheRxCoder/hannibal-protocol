# Hannibal Protocol — 0.6.0-beta.1 (simulation)

*Strategic intelligence. Bounded defense.* A local-first, multi-agent endpoint
security package for Windows 11. This beta runs in **simulation mode**: it
observes, correlates, decides and records, and its containment broker has no
effector. It runs alongside Microsoft Defender and does not replace it.

Start here:
- `docs/BETA_README.md` — install, drill, uninstall, expected behaviour
- `docs/DESIGN_METAPHOR_MODEL.md` — Hannibal, Scipio, Fu Hao, Abu Yusuf Ya'qub al-Mansur, Hatshepsut
- `docs/METHOD_PART3_V06.md` — what was built, decisions, gaps
- `docs/BETA_TEST_PLAN.md` — Windows validation checklist
- `docs/METHOD_PART2_REVIEW_V05.md` — the v0.5 safety rules, still in force

## Layout

| Path | Contents | Built and tested here? |
| --- | --- | --- |
| `src/Hannibal.Contracts` | Shared records and interfaces | Yes |
| `src/Hannibal.Overwatch` | Safe policy engine, K-Means scorer | Yes |
| `src/Hannibal.Core` | Journal, ingestion, agents, ladder, decoys, broker, bundles, snapshot | Yes |
| `src/Hannibal.Simulator` | Synthetic end-to-end drill; decoy cleanup for uninstall | Yes |
| `src/Hannibal.Windows` | Authenticode, file identity, ACL'd pipes, decoy deployment, service bodies | Type-checked |
| `src/Hannibal.Windows.Etw` | ETW collectors (TraceEvent) | Written; validate on Windows |
| `src/Hannibal.CoreService`, `src/Hannibal.ContainmentBroker` | Windows service hosts | Written; validate on Windows |
| `src/Hannibal.Desktop` | WPF dashboard (brand guide v1.0) | Written; validate on Windows |
| `db/` | SQLite migrations 001–003, broker schema | Yes |
| `ml/` | Trainer, evaluator, detector comparison, shadow gate | Yes |
| `graph/` | Python time-respecting investigator | Yes |
| `kg/` | ATT&CK knowledge-graph builder and rule map | Yes |
| `tools/` | Offline signing, indicator payloads, beta bootstrap, dashboard preview renderer | Yes |
| `docs/images/` | Dashboard preview rendered from a drill snapshot | Yes |
| `deploy/` | publish / install / uninstall (PowerShell) | Written; validate on Windows |
| `tests/` | C# runners, Python tests, cross-language signature fixtures | Yes |

## Build and test

```
python -m pytest -q tests/python
dotnet run --project tests/Hannibal.Core.Tests
dotnet run --project tests/Hannibal.SmokeTests
dotnet run --project src/Hannibal.Simulator -- drill-out
```

On Windows: `python tools/bootstrap_beta_signing.py`, then `pwsh deploy/publish.ps1`.

## Licence and use

Copyright GneissLife Innovations. Licensed under the GNU General Public License
v3.0; see `LICENSE`. Third-party components keep their own licences; see
`THIRD_PARTY_NOTICES.md`. Arrange explicit ownership terms with any contractor
before production use. Use only on devices you own or are authorised to test.
