# Hannibal Protocol 0.6.0-beta.1 — Beta Test Plan

Run everything on a dedicated Windows 11 VM with a snapshot. No production
credentials. Nothing here authorises enforcing mode.

## 1. Automated suites (must pass before any publish)

| Suite | Command | Count at release |
| --- | --- | --- |
| Core runtime (C#) | `dotnet run --project tests/Hannibal.Core.Tests` | 142 checks |
| Policy smoke (C#) | `dotnet run --project tests/Hannibal.SmokeTests` | 11 checks |
| Python (schema, SQL catalogue, ML, graph, signing, KG) | `python -m pytest -q tests/python` | 75 tests |
| Drill | `dotnet run --project src/Hannibal.Simulator -- drill-out` | completes; both audit chains intact |

On Windows the core suite also exercises ML-DSA-65 signing, which this build's
authoring environment could not run.

## 2. Build validation on Windows (not yet performed)

The PowerShell scripts were checked for structure only; run `Invoke-ScriptAnalyzer deploy` first.

- [ ] `dotnet build HannibalProtocol.sln -c Release` succeeds, including
      `Hannibal.Windows.Etw`, both services and `Hannibal.Desktop`.
- [ ] Confirm `Microsoft.Diagnostics.Tracing.TraceEvent` 4.0.0 restores and that `TraceEventSession`, `EnableProvider`, `EventsLost` and `Source.Dynamic` behave as the collectors assume.
- [ ] The dashboard opens `drill-out\snapshot.json` and renders every panel.
- [ ] Confirm WPF picks up the embedded fonts (family names `DM Sans 9pt` and `IBM Plex Mono`); check the layout at 100%, 150% and 200% scaling.
- [ ] Before public release, replace the Latin-subset beta fonts with the official full TTFs (see `src/Hannibal.Desktop/Fonts/README.md`).

## 3. Collector acceptance (ETW)

For each provider in `EtwCollectors.cs`:

- [ ] Confirm the GUID with `logman query providers <name>`.
- [ ] Capture a short trace and confirm the event IDs and payload field names
      the mapping uses (`ProcessID`, `ParentProcessID`, `CreateTime`,
      `ImageName`, `PID`, `daddr`, `dport`, `FileName`, `KeyName`, `ValueName`).
      Correct the mapping where your build differs.
- [ ] Confirm `NT SERVICE\HannibalCore` with Performance Log Users membership
      can open the real-time sessions. If not, record the error and the
      minimum privilege that works.
- [ ] Generate load (a build or a large copy) and confirm lost events are
      reported, Sentry turns *degraded*, and new actions are declined.
- [ ] Confirm a stale `Hannibal-RT-*` session from a killed process is cleaned up on restart.

## 4. Installation and permissions

- [ ] `install.ps1` without `-DeployDecoys` creates no files in user folders.
- [ ] `%ProgramData%\Hannibal\core` and `broker` are not readable by a standard user.
- [ ] `status\snapshot.json` is readable by a standard user and contains no decoy file names.
- [ ] Defender is still active and unchanged (`Get-MpComputerStatus`).
- [ ] `uninstall.ps1` removes the services, the shortcut and unchanged decoys only.

## 5. Broker boundary

- [ ] As a standard user, opening `\\.\pipe\HannibalProtocol.Broker.v1` fails (ACL).
- [ ] Pre-creating the pipe name before the broker starts makes the broker fail
      to start (FirstPipeInstance); it does not join the squatted pipe.
- [ ] A frame with a wrong MAC gets no reply and is logged in the broker audit chain.
- [ ] Kill the broker during a simulated action; on restart the intent is
      `FAILED_ON_CRASH` and a retry with the same idempotency key does nothing new.

## 6. Decoys

- [ ] Placement skips OneDrive-redirected folders.
- [ ] Defender full scan, Windows Search and File History produce **no** incidents.
- [ ] Opening a decoy in Explorer's preview pane: record the result (expected: no incident for signed readers).
- [ ] An unsigned test program that renames a decoy produces an Alert.

## 7. Safe behavioural checks

- [ ] EICAR test file (download through the AMTSO feature-settings check page,
      or create it locally): expect a simulated quarantine and a working restore.
- [ ] Atomic Red Team persistence tests for Run keys (T1547.001), in the VM only:
      record which axes produced observations.

## 8. False-positive soak

At least 14 days on at least 10 consenting machines with ordinary use
(installs and updates, games, developer tools, low-end hardware). Report false
alert **episodes** per endpoint-week, not per window. The proposed gate is ≤ 1.

## 9. Exit criteria for an enforcing pilot (not part of this beta)

An enforcing build needs all of these, plus an independent review:
a WFP dynamic-session effector with crash re-application tests; catalog
signature verification; a calibration study signed off in a policy bundle;
the soak gate met; and code signing (for example Azure Trusted Signing) on
every binary.
