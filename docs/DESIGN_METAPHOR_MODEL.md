# Hannibal Protocol — Design Metaphor Model

**Version:** 0.6.0-beta.1 · **Status:** design reference · **Applies to:** code names, documentation, product narrative

## 1. Purpose and guardrails

The historical figures in this model give the team a shared vocabulary for
*defensive* mechanisms. Each figure maps to a specific part of the code. Each
mapping states what the metaphor must **not** imply.

Rules that apply to every motif:

1. **These are contemporary design associations.** They are not historical
   insignia, and they do not claim the figures shared a doctrine (brand guide v1.0, p. 8).
2. **The metaphors are defensive and local.** No motif justifies any action
   off the user's device. There is no hack-back, no scanning of third parties
   and no interference with attacker infrastructure. "CounterOffensive" means
   local, reversible countermeasures only.
3. **Code names stay internal.** The dashboard uses plain functional names
   ("Trust gates", "Record", "Recursive learning"). Battle language and absolute
   protection claims never appear in the product voice.
4. **A metaphor is not evidence.** Design strength comes from the tests and the
   evaluation data, not from history.

## 2. Hierarchy

| Tier | Figure | Motif in the product | Brand device |
| --- | --- | --- | --- |
| Primary | **Hannibal Barca** | *The Maneuver*: adaptive, bounded, asymmetric defense | Primary mark |
| Primary (counterpart) | **Scipio Africanus** | *The Relay*: study the opponent, adapt under review | Supporting symbol |
| Secondary | **Fu Hao** | *The Ambush and the Record* | — |
| Secondary | **Abu Yusuf Ya'qub al-Mansur** | *The Ribat*: the verified boundary | — |
| Secondary | **Hatshepsut** | *Logistics and Restoration* | — |

---

## 3. Primary theme — Hannibal and Scipio

| Historical pattern | Defensive principle | Where it lives |
| --- | --- | --- |
| Cannae: a centre that yields, then closes | **The Maneuver ladder.** The response tightens one bounded rung at a time: Observe → Watch → EnvelopEgress → Hold. Every rung has a TTL, and a rung steps down when its support expires. | `src/Hannibal.Core/Maneuver/IsolationLadder.cs` |
| Trebia: the concealed reserve | **A second capture channel.** A network action needs two raw observations on different sensors with disjoint root events. | `TrustedIngestor.cs`, `SafeOverwatchPolicyEngine.cs` |
| The Alps: the unexpected axis | **Approach-axis coverage.** Every persistence and egress route is shown as watched, degraded or unwatched. Nothing is implied covered. | `Relay/ModelAndCoverage.cs` (`AxisCoverage`) |
| A coalition of heterogeneous troops | **Corroboration across detectors.** Rules, decoys, indicators and ML each keep their own provenance. Derived findings never count twice. | `HannibalStore.ResolveRoots`, evidence derivations |
| Scipio studies and inverts the opponent | **The Relay loop.** Curate → evaluate → shadow → review. Models are compared against baselines on held-out data, run in shadow, and are proposed for release only by a gate and a human. | `ml/compare_detectors.py`, `ml/shadow_gate.py`, `SignedModelLoader` |

---

## 4. Secondary theme — Fu Hao: *The Ambush and the Record*

**Historical basis.** Fu Hao (died c. 1200 BC) was a consort of King Wu Ding of
the Shang dynasty who served as a military general and high priestess. She is
known almost entirely from oracle-bone inscriptions and from her tomb at Yinxu,
which was excavated intact in 1976 by Zheng Zhenxiang. The inscriptions record
her campaigns. The one against the Ba is remembered as the earliest recorded
large-scale ambush in Chinese history. In that campaign she commanded forces
that included the generals Zhi and Hou Gao. Her tomb held a large bronze and
jade assemblage, including roughly 755 jade objects.

| Association | Defensive principle | Where it lives |
| --- | --- | --- |
| The ambush against the Ba | **Decoys (MITRE D3FEND D3-DF, D3-DUC).** Decoy files and decoy credential exports sit where bulk encryption reaches first. They are larger than 1 KiB, vary in size, carry correct file signatures, are hidden and are excluded from indexing. A touch on a decoy is **one** observation, never a verdict. Expected scanners (Defender, the indexer) are allowlisted only when their signature is trusted. | `Deception/Canaries.cs`, `Hannibal.Windows/Deployment.cs` |
| Known from inscriptions, not legend | **Evidence-bound explanation.** Every sentence in an incident carries the raw root IDs it rests on. A claim with no root is refused. Hypotheses are labelled as hypotheses. | `Analysis/Explanation.cs` |
| Bronze: cast once | **Immutable artifacts.** The audit log is a hash chain, so an edited entry is detectable. Bundles are signed and never edited in place. | `Storage/AuditChain.cs` ("bronze record") |
| Joint command with Zhi and Hou Gao | **No single sensor decides.** Containment needs independent capture channels. | Overwatch quorum |

**Guardrails.** Decoys are local tripwires, not traps for third parties.
Decoy file names never leave the ACL-restricted core database: the status
snapshot names a decoy only by ID and parent folder. Uninstall removes a decoy
only if its content is unchanged.

**UI expression.** The "Record" panel shows audit entries, chain integrity and
decoys deployed or touched. Each claim in an incident lists its evidence roots.

---

## 5. Secondary theme — Abu Yusuf Ya'qub al-Mansur: *The Ribat*

**Identification.** "Yusef Jakob Al-Mansour" is read as **Abū Yūsuf Yaʿqūb
al-Manṣūr** (Ya'qub is the Arabic form of Jacob), the third Almohad caliph,
who reigned 1184–1199. An earlier research pass associated "Al-Mansour" with the
Abbasid caliph who founded Baghdad. This model follows the identification above.

**Historical basis.** Al-Mansur defeated Alfonso VIII of Castile at the Battle
of Alarcos (July 1195). He began a new fortified imperial capital, Ribat
al-Fath (today's Rabat), whose walls and gates (such as Bab er-Rouah) form the
outer walls of the historic city. Its great mosque was begun around 1191 and
was left unfinished at his death; the Hassan Tower is its minaret. A *ribat* is
a fortified post on a frontier.

| Association | Defensive principle | Where it lives |
| --- | --- | --- |
| The ribat: a fortified post at the boundary | **The Containment Broker.** The only component that may ever act sits behind its own boundary and trusts nothing it is told. It authenticates the frame (HMAC), rejects replays (counter + nonce, persisted across restarts), re-derives scope and protected targets, verifies the policy and indicator bundles from **its own** copies, re-hashes the file through a bound handle, writes an intent **before** acting, and can always roll back. In the beta it has **no effector**. | `Ribat/SimulationBroker.cs`, `Ribat/ProtectedTargets.cs`, `Hannibal.Windows/Pipes.cs` |
| Walls with gates | **Concentric trust gates.** OS observation → authenticated collector → trusted journal → raw root record → policy evaluator → broker re-verification. Each gate checks independently, and the dashboard shows the state of each one. | `StatusSnapshot.TrustGates` |
| Alarcos: action after the forces are assembled | **Corroborate, then act.** A response is proposed only after independent observations are assembled and fresh. Stale evidence makes the response yield. | Overwatch quorum, ladder TTLs |
| The unfinished mosque | **Never present the unfinished as finished.** Unwatched axes, unimplemented features and uncalibrated scores are stated plainly in the product and the docs. | Dashboard notices, `docs/METHOD_PART3_V06.md` §6 |

**Guardrails.** The ribat defends this device's boundary. It has no command for
anything off-device and no generic command runner; unknown or numeric command
values are refused.

**UI expression.** The "Trust gates" panel. Simulated actions are always shown
with "No change was made to this device."

---

## 6. Secondary theme — Hatshepsut: *Logistics and Restoration*

**Historical basis.** Hatshepsut ruled as an 18th-dynasty pharaoh (c. 1479–1458
BCE). She re-established trade networks disrupted during the Hyksos period and
funded the expedition to the Land of Punt (around her ninth regnal year). The
voyage is commemorated in reliefs at her temple at Deir el-Bahari. She was one
of Egypt's most prolific builders: Karnak, the Red Chapel and Djeser-Djeseru at
Deir el-Bahari, the last overseen by her official Senenmut. Her reign is
remembered mainly for trade and building, although she also sent raiding
expeditions to Byblos and Sinai. After her death many of her monuments were
defaced. Her record was recovered by later scholarship.

| Association | Defensive principle | Where it lives |
| --- | --- | --- |
| The Punt expedition: a supply line | **Signed logistics.** Everything that enters from outside (policy, indicators, models) arrives as a signed, versioned, expiring bundle. Keys are pinned in the installer; a signature threshold is supported; expiry blocks freeze attacks; monotonic versions block rollback. The design is simplified from The Update Framework (TUF). | `Crypto/SignedBundle.cs`, `Restoration/Bundles.cs`, `tools/hannibal_sign.py` |
| Reliefs that document the voyage | **Provenance of every delivery.** Each accepted or rejected bundle is recorded with its hash in the audit chain. | `BundleIntake` audit entries |
| Restoration, not conquest | **Every action is reversible.** Restore tokens, idempotent rollback, quarantine that never deletes, TTL expiry, and an uninstaller that removes only what it placed. | `SimulationBroker.Rollback`, `CoreRuntime.Restore`, `CanaryCleanup` |
| A builder with an architect | **Disciplined deployment.** Tests gate publishing; the installer states exactly what it changes; staged rings, as Microsoft's MVI safe-deployment practices require, come before any wider rollout. | `deploy/publish.ps1`, `deploy/install.ps1` |
| Defaced monuments, recovered record | **Tamper-evident history.** An erased or edited entry is detectable by anyone holding a later chain head. Detection, not prevention: a local administrator remains an advanced adversary. | `AuditChain.FirstBrokenLink` |

**Guardrails.** Consolidation, not expansion: no feature reaches beyond the
device. Indicator feeds are used only under licences that permit it.

**UI expression.** The bundle list and the "Recursive learning" panel. The
Relay symbol is used only with its label, never as an approval seal.

---

## 7. Component crosswalk

| Component | Primary motif | Secondary motif | Beta status |
| --- | --- | --- | --- |
| Trusted ingestor and journal | Coalition | Fu Hao (record) | Implemented, tested |
| Decoys | Trasimene | **Fu Hao** (ambush) | Implemented; Windows deployment written, not run |
| Overwatch policy | Coalition / Trebia | **Al-Mansur** (corroborate, then act) | Implemented, tested |
| Isolation ladder | **Cannae** | — | Implemented; actions simulated |
| Containment Broker | Trebia reserve | **Al-Mansur** (ribat) | Simulation only, tested |
| Signed bundles | — | **Hatshepsut** (logistics) | Implemented, tested (ECDSA; ML-DSA where the OS supports it) |
| Restore and rollback | — | **Hatshepsut** (restoration) | Implemented, tested |
| Audit hash chains | — | **Fu Hao** (bronze) / **Hatshepsut** (recovered record) | Implemented, tested |
| ModelLab and shadow gate | **Scipio** (Relay) | — | Implemented, tested offline |
| Axis coverage | **Alps** | **Al-Mansur** (unfinished mosque) | Implemented |
| Knowledge graph | Scouting | Fu Hao (inscriptions) | Builder implemented; no language model |

## Sources

- Fu Hao: https://en.wikipedia.org/wiki/Fu_Hao
- Yaqub al-Mansur: https://en.wikipedia.org/wiki/Yaqub_al-Mansur
- Hassan Tower / Ribat al-Fath: https://en.wikipedia.org/wiki/Hassan_Tower
- Almohad architecture: https://en.wikipedia.org/wiki/Almohad_architecture
- Hatshepsut: https://en.wikipedia.org/wiki/Hatshepsut
- Temple of Hatshepsut: https://www.worldhistory.org/article/1100/the-temple-of-hatshepsut/
- MITRE D3FEND Decoy Object: https://d3fend.mitre.org/technique/d3f:DecoyObject/
- Hannibal Protocol Brand & Style Guide v1.0 (10 Nov 2026)
