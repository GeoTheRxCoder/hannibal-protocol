# Hannibal Protocol 0.6.0-beta.1 — Simulation Beta

*Strategic intelligence. Bounded defense.*

## What this beta is

A Windows 11 endpoint-security **preview that runs in simulation mode**. It
collects local telemetry, places decoy files (opt-in), correlates evidence
across independent sensors, applies a conservative signed policy, and records
what it **would** do. The Containment Broker re-verifies every proposed action
and records it as simulated. **Nothing on the machine is blocked, moved,
deleted or terminated.**

## What it is not

- It is not a replacement for Microsoft Defender. Defender stays active and
  Hannibal does not change its settings. Registering with Windows Security
  Center requires Microsoft Virus Initiative membership, which this project
  does not have.
- It does not make protection claims. Severity and confidence are uncalibrated
  ordering heuristics. The drill demonstrates decision logic on synthetic input
  and is not evidence of real-world protection.
- It has no cloud component. Nothing leaves the device.

Suggested wording for testers: *"Simulation-mode preview. Detections are
advisory. Not a replacement for Microsoft Defender."*

## Requirements

- Windows 11 (x64), administrator rights, ideally a VM with a snapshot
- .NET 10 SDK (build) or .NET 10 Desktop Runtime (run)
- Python 3.11+ with `cryptography` (signing workstation only)

## Quick start

### 1. Try the drill (any OS with .NET 10, no installation)

```
dotnet run --project src/Hannibal.Simulator -- drill-out
```

The drill runs all seven agents and the broker in one process against synthetic
observations, then writes `drill-out/snapshot.json`. On Windows, open it in the
dashboard:

```
dotnet run --project src/Hannibal.Desktop -- drill-out\snapshot.json
```

### 2. Create signing material (once, offline)

```
pip install cryptography
python tools/bootstrap_beta_signing.py --out signing-workspace
```

This creates:
- a private release key in `signing-workspace/keys/` (keep it offline; never ship it);
- `deploy/trust/trust-root.json`, which the build copies into the services;
- signed `policy` (simulation, calibration **not** attested) and `indicators`
  (EICAR test hash only) bundles in `signing-workspace/bundles/`. They expire
  in 30 days.

### 3. Build and install on the test machine (elevated PowerShell)

```
pwsh deploy/publish.ps1
cd artifacts\HannibalProtocol-0.6.0-beta.1
.\install.ps1 -Bundles ..\..\signing-workspace\bundles            # add -DeployDecoys to place decoy files
```

`publish.ps1` runs the test suites first and refuses to publish if any test fails.

### 4. Use

- Dashboard: Start menu > **Hannibal Protocol (beta)**. It is read-only and
  unprivileged. It always shows environment, scope and simulation state.
- Logs: Event Viewer > Application (sources `HannibalCore`, `HannibalBroker`).
- Data: `%ProgramData%\Hannibal\` (core journal, broker intent log, audit chains).

### 5. Uninstall

```
.\uninstall.ps1               # keeps data; add -RemoveData to delete it
```

Decoy files are removed only if their content is unchanged since deployment.

## What you will see

| Situation | Expected result |
| --- | --- |
| Defender or the indexer reads a decoy | Nothing (expected reader) |
| An unsigned process modifies a decoy | Incident; **Alert** |
| One suspicious connection | Alert; no action |
| The same connection seen by two sensors | Still one observation; no action |
| Two separate connections on two sensors | With the beta policy: Alert (calibration not attested). With a calibrated policy: simulated 900-second egress envelope |
| The EICAR test file hashed | Simulated quarantine with a restore token |
| Evidence goes stale / TTL ends | The ladder steps down; the simulated action expires |
| A sensor drops events | Health degrades; new actions are declined |

## Known limitations

See `docs/METHOD_PART3_V06.md` §6. In brief: the ETW collectors, services,
installer and dashboard were written without Windows build access and must be
validated on Windows (`docs/BETA_TEST_PLAN.md`). There is no effector. Catalog
signature lookup is pending. The embedded fonts are Latin-only subsets for the beta.

## Reporting

Record: Windows build, what you did, what the dashboard showed, and the
`Application` event log entries. Attach `%ProgramData%\Hannibal\status\snapshot.json`.
Do not attach `core.db`: it contains local file paths.
