# Third-party notices — Hannibal Protocol 0.6.0-beta.1

| Component | Use | Licence |
| --- | --- | --- |
| .NET 10 runtime and libraries | All C# components | MIT |
| Microsoft.Extensions.Hosting.WindowsServices | Service hosting | MIT |
| Microsoft.Diagnostics.Tracing.TraceEvent | ETW collectors | MIT |
| SQLite (winsqlite3.dll, part of Windows) | Journal and broker storage | Public domain |
| scikit-learn, NumPy, pandas | Offline ModelLab only | BSD-3-Clause |
| cryptography (Python) | Offline signing tool only | Apache-2.0 / BSD |
| DM Sans (Copyright 2014 The DM Sans Project Authors), IBM Plex Mono (Copyright 2017 IBM Corp.) | Dashboard typefaces, embedded | SIL Open Font License 1.1 — full texts in `src/Hannibal.Desktop/Fonts/OFL-*.txt` |
| MITRE ATT&CK data | Optional local knowledge graph | MITRE ATT&CK Terms of Use — reproduce MITRE's copyright notice when distributing a built graph |

Indicator feeds: no third-party hash feed is bundled. The beta indicator bundle
contains only the EICAR anti-malware test-file hash. Confirm the licence of any
feed (several abuse.ch feeds require a commercial licence for for-profit use)
before adding its hashes to a signed bundle.

The Hannibal Protocol symbol in `src/Hannibal.Desktop/Assets` is a raster taken
from the brand guide v1.0 and is subject to the trademark caveat stated there
(availability not yet assessed).
