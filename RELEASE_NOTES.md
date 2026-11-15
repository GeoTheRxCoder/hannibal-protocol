# Hannibal Protocol 0.6.0-beta.1 — release notes (14 Nov 2026)

**Simulation beta for Windows 11 test machines.** No containment action changes
the device. Runs alongside Microsoft Defender.

## New
- Seven-agent Core runtime on a crash-consistent SQLite journal.
- Trusted ingestion with authenticated collectors and canonical raw roots.
- Decoy files and decoy credential exports (opt-in, elevated installer step).
- The Maneuver isolation ladder (TTL-bound, one rung per evaluation).
- Containment Broker in simulation: authenticated IPC, replay protection, independent re-verification, intent log, rollback.
- Signed policy, indicator and model bundles (ECDSA P-256; ML-DSA-65 where supported) and an offline signing tool.
- Tamper-evident audit hash chains in both services.
- WPF operations dashboard per brand guide v1.0 (read-only), with embedded DM Sans / IBM Plex Mono.
- ModelLab: detector comparison with grouped bootstrap; shadow-promotion gate.
- Local ATT&CK knowledge-graph builder; evidence-bound explanations.
- Design metaphor model: Hannibal, Scipio, Fu Hao, Abu Yusuf Ya'qub al-Mansur, Hatshepsut.

## Verified in the build environment (Linux, .NET 10.0.115)
142 core checks, 11 policy smoke checks, 75 Python tests, synthetic drill.

## Not yet verified
Windows build and runtime of the ETW collectors, services, installer and
dashboard. See `docs/BETA_TEST_PLAN.md`.

## Not included
Any effector (network block, quarantine move, termination), cloud features,
language model, code signing. See `docs/METHOD_PART3_V06.md` §6.
