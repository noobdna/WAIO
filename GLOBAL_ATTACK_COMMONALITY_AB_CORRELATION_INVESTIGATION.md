# WAIO GLOBAL RED ALERT — Global Attack Commonality & A→B Correlation Investigation

- Prepared: 2026-10-14
- Scope: defensive, passive OSINT research and architecture design only. No third-party system was scanned, probed, or accessed. No containment, blocking, shutdown, or remediation action was executed. No production service was modified. No secrets were collected or exposed.
- Companion machine-readable file: `GLOBAL_ATTACK_COMMONALITY_AB_CORRELATION_INVESTIGATION.json`
- Relationship to existing WAIO documents: this report is a point-in-time refresh and extension, not a replacement, of `GLOBAL_THREAT_INTELLIGENCE_ASSESSMENT.md` (prepared 2026-10-09) and `THREAT_LANDSCAPE_PATROL_ANALYSIS.md` (2026-10-02). The 2026-10-09 assessment already covers worldwide incidents up to its own date; this report's incident register deliberately starts from 2026-09-14 and overlaps only where a new angle (explicit A→B correlation analysis) applies. Where a finding repeats the 2026-10-09 assessment, it is marked `[REPEATS 10-09]`; new material is unmarked.
- This document is **research and design only**. No code was written or modified as part of this investigation — recommendations in §7/§9 are proposals for separate, reviewable follow-up work, exactly as the mission's constraints require.
- **STATUS UPDATE (2026-10-14, same day, follow-on task)**: the §7.7/§9-item-1 recommendation below (the code-enforced global-only containment ceiling) has since been **implemented, tested, and documented** as ARCHITECTURE.md Phase 104. This section and the findings below are left UNCHANGED from the original research — they are the evidence that motivated the fix, not a description of it. See ARCHITECTURE.md's own Phase 104 entry for what was actually built, and `security/decision_engine/decision_engine_lib.py`'s own `local_corroboration_for_profile()` / `security/red_alert/containment_approval_lib.py`'s own `has_trusted_local_corroboration()` for the code itself. §7.1–7.4 (IOC normalization, time-window correlation, the A→B relationship graph) and §9 items 2–5 remain proposals only, not yet implemented.

---

## 0. Minimum Safe Next Steps (read this first)

Before anything else, the three concrete, low-risk actions this investigation surfaces:

1. **Close a structural gap, not just an operational one**: today, nothing in `decision_engine_lib.py` encodes "a global-only correlation (no local telemetry corroboration) must never reach `RECOMMEND_CONTAINMENT`" — that outcome currently holds only because no execution path exists anywhere downstream of the Containment Approval Gate yet. That is a safe accident, not a guarantee. See §8 and §9 item 1. **[DONE 2026-10-14 — ARCHITECTURE.md Phase 104; see the status note above.]**
2. **Backfill ARCHITECTURE.md Phase D/E documentation** for the containment approval gate (commits `e6559e5`, `7983f08`) — code and tests already exist and are merged; only the architecture doc entry is missing. Pure documentation, zero behavior change, recommended as a same-day housekeeping item, not bundled into this report's own scope.
3. **Do not schedule `red_alert_cron.sh` yet.** It is deliberately manual-only today. Nothing in this investigation changes that recommendation — if anything, §8's finding (global-only evidence can already reach `RECOMMEND_CONTAINMENT` on paper) argues for closing item 1 *before* any scheduling conversation happens.

---

## 1. Executive Summary

**What was investigated:** 11 significant, publicly reported cyber incidents from 2026-07-14 through 2026-10-14 (one, Oracle Health/Cerner, surfaced via a regulatory filing about a 2025 breach — included deliberately, see §5), compared across initial access, identity compromise, lateral movement, shared infrastructure, persistence, supply-chain abuse, and impact, specifically hunting for genuine attack-chain (A→B) relationships rather than coincidental technique overlap.

**Headline finding:** across this window, there is exactly **one** confirmed, vendor-documented A→B relationship between separate public incidents — the ChainDrop/keyv npm-supply-chain worm propagating from one compromised maintainer into named downstream organizations' build pipelines (§4, Finding R1). Every other apparent connection in the dataset is either a shared *tooling lineage* with weakening attribution (the broader Shai-Hulud npm-worm family, §5 H1) or a shared *technique* with no evidence of a shared actor, campaign, or infrastructure (edge-device exploitation in the Integrity-Tech/Raptor-Train and Ivanti Connect Secure cases, §5 H2). The investigation deliberately did not find, and does not claim, a sweeping single-campaign narrative tying ransomware/OT incidents (IDCF Cloud, Ahold Delhaize, the French supermarket refrigeration attack) to the espionage/supply-chain cluster — no evidence supports that, and asserting it would be fabrication.

**Second finding, about WAIO itself:** the repository already has a materially more mature correlation and human-gating pipeline than a from-scratch design would assume — a five-collector Incident Learning Engine, a cross-country pattern-correlation module (`critical_infra_watch.py`), an auditable 0-100 confidence formula, a Decision Engine with an explicit `multi_source` signal, and (as of commits `e6559e5`/`7983f08`) a hardened, execution-free Containment Approval Gate. The missing piece is narrower than "build a correlation engine": it is (a) a true cross-incident **IOC/infrastructure** normalization layer (today's correlation is attack-pattern-string matching only), (b) an explicit **occurrence-date, not publication-date**, time-window correlator (the Oracle Health case shows why this matters), (c) a **relationship-confidence** score distinct from incident confidence, and (d) a **code-enforced** (not merely accidental-by-omission) rule that global-only evidence has a hard ceiling below containment. See §7–§9.

**What was not done:** no code was changed, no cron job was scheduled, no containment action (real or simulated-as-real) was taken, and no claim in this report is asserted beyond what its cited source actually supports.

---

## 2. Top Recurring Attack Patterns

Ranked by how many *independent* incidents in the register exhibit each pattern — not by narrative importance:

1. **Open-source supply-chain / maintainer-trust abuse** (4 of 11 incidents: Mini Shai-Hulud, ChainDrop/keyv, tensorlake npm package, @subql/common npm package). The single most repeated *mechanism* in the window, but — critically — these are mostly the same worm *lineage* reusing/forking a publicly leaked toolchain, not 4 independent actors converging on the same idea. See §5 H1 for why attribution weakens after the May 2026 public leak.
2. **Edge/perimeter-appliance exploitation as a durable access vector** (2 incidents: Integrity Technology Group-enabled PRC campaign via Raptor Train-class botnets of unmonitored routers/appliances; the Ivanti Connect Secure zero-day chain exploited by UTA0576). Same *technique class*, different actors, different infrastructure — a recurring industry-wide pattern, not a link between these two specific incidents.
3. **Trusted-relationship abuse as a business model, not just a technique** (Integrity Tech as a commercial enabler of state-actor botnet infrastructure; open-source maintainers as an abused trust anchor). Structurally similar at the "abuse of an asymmetric trust relationship" level; organizationally and operationally unrelated.
4. **Unauthenticated API / architectural-flaw exploitation, not CVE exploitation** (CenterPoint Energy — mass enumeration of a public API with no WAF/rate-limit/JWT verification). A single incident in this window, but notable because it is invisible to any IOC- or CVE-based detection — the signal is internal telemetry (rate-limit/anomaly data), not external threat intel. Directly relevant to §7's point that not every detection gap can be closed by better global correlation.
5. **Ransomware with availability/OT impact, geographically dispersed, no shared actor identified** (IDCF Cloud/Japan, Ahold Delhaize/US grocery chains, French supermarket refrigeration). Three incidents, three different sectors/countries, zero shared IOCs or attribution in the public record as of 2026-10-14 — a trend worth watching, not a connected campaign.

---

## 3. Incident Comparison Table

Confidence legend: **CONFIRMED** = official/victim/vendor-confirmed; **CREDIBLE** = multi-source corroboration, nothing rebutted; **SELF-CLAIM** = attacker's or single party's own claim only, not independently verified.

| # | Incident | Date (occurred → disclosed) | Sector / Geo | Initial Access | Attribution (confidence) | Source |
|---|---|---|---|---|---|---|
| 1 | Integrity Technology Group / Raptor Train-class botnet campaign | ongoing → advisory 2026-10-08 | Global critical infra | Edge/router/appliance targeting at scale | PRC state-linked (CONFIRMED, joint CISA/FBI/NSA + intl. partners) | [CISA AA26-281A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a) |
| 2 | Ivanti Connect Secure zero-day chain (CVE-2026-104935 + 2) | exploitation from 2026-10-03 → CISA KEV 2026-10-13 | VPN/edge appliance, cross-sector | Auth-bypass → unauthenticated RCE, in-memory only (evades Ivanti's own Integrity Checker Tool) | "UTA0576" — new Volexity cluster (CREDIBLE exploitation; actor identity unconfirmed) | [Volexity](https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/), [CISA](https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerability-ivanti-connect-secure) |
| 3 | Mini Shai-Hulud npm/PyPI worm wave | 2026-05-11/12 | Dev tooling / AI supply chain | CI cache-poisoning, npm OIDC publishing-endpoint abuse, 172 packages | "TeamPCP" initial assessment (CREDIBLE, weakened — toolchain later leaked publicly) | [Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-ai-supply-chain-20260517-csa-st/), [Akamai](https://www.akamai.com/blog/security-research/mini-shai-hulud-worm-returns-goes-public) |
| 4 | ChainDrop worm — keyv npm ecosystem | discovered 2026-08-04 | Software supply chain | Compromised `keyv` maintainer creds, preinstall-hook payload, 400+ packages | Unattributed to a named actor; technical mechanism CONFIRMED (Elastic, StepSecurity) | [Elastic Security Labs](https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain), [StepSecurity](https://www.stepsecurity.io/blog/chaindrop-npm-worm) |
| 5 | tensorlake npm package compromise | 2026-09-23 | AI SDK supply chain | Compromised package v0.5.144, same worm-family mechanics | Same lineage as #3/#4, actor unconfirmed (CREDIBLE technical, LOW attribution) | [TheHackerNews](https://thehackernews.com/2026/10/tensorlake-npm-package-compromised-to.html) |
| 6 | @subql/common npm hidden payload | analyzed 2026-10-05 | CI/cloud credential theft | Hidden installer payload, credential collector + remote shell | Unattributed | [StepSecurity](https://www.stepsecurity.io/blog/5-supply-chain-attacks-in-48-hours-why-securing-one-layer-is-not-enough) |
| 7 | CenterPoint Energy customer-data exposure | disclosed ~2026-09-17 | Energy, US | Unauthenticated public-API mass enumeration (no CVE — architectural flaw) | Self-claimed by attacker "4d722e4d656f77"; breach CONFIRMED by CenterPoint | [BleepingComputer](https://www.bleepingcomputer.com/news/security/centerpoint-energy-confirms-customer-data-stolen-in-cyberattack/) |
| 8 | Ahold Delhaize USA grocery chains (Stop & Shop/Hannaford/Giant/Food Lion) | 2026-10-11/12 | Retail/grocery, US | Not publicly disclosed | INC Ransom SELF-CLAIM only, not independently verified at time of writing | [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/ahold-delhaize-data-breach-2m/) |
| 9 | IDCF Cloud (IDC Frontier/SoftBank subsidiary) | 2026-10-07 | Cloud/MSP, Japan — 495 downstream orgs incl. govt | Not disclosed; privesc to hypervisor level, 239 hypervisors / 16,000 VM disks / 3.6PB exfil | Unattributed, no leak-site post (impact CONFIRMED by BleepingComputer reporting) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ransomware-attack-disrupts-japans-idcf-cloud-used-by-govt-clients/) |
| 10 | French supermarket refrigeration OT attack | 2026-10-13 | Retail/OT, France, 250–350 stores | Not disclosed; remote manipulation of refrigeration control systems | Unattributed | [BleepingComputer](https://bleepingcomputer.com/news/security/cyberattack-shuts-down-refrigerators-at-french-supermarkets) |
| 11 | Oracle Health (Cerner) legacy-server breach | occurred 2025-01-22→2025-04-01 → disclosed via TX AG filing 2026-10-06 | Healthcare, US, ~20M patients / 80 hospitals | Stolen credentials against un-migrated legacy servers | Solitary actor, not a known ransomware group (MEDIUM per reporting) | [Rescana](https://www.rescana.com/post/oracle-health-cerner-2026-data-breach-exposes-nearly-20-million-patient-records-across-80-u-s-hospitals) |

**Note on #11**: its occurrence date is ~18 months outside the nominal 90-day window; it is included only because its *disclosure* just happened. This is deliberately used as the motivating example for §7's "disclosure date ≠ incident date" design rule.

---

## 4. Confirmed A→B Relationships and Supporting Evidence

**R1 — ChainDrop/keyv (#4) → named downstream organizations (CONFIRMED).**
Evidence: Elastic Security Labs and StepSecurity both independently published the propagation mechanism (preinstall-hook payload executing on dependency install/update) and named the downstream organizations exposed by it — Deliveroo, Ornikar, OneReach, Picsart, Qlik, ServiceTitan — within a documented ~4-hour propagation window from the initial `keyv` maintainer-credential compromise.
Strength of evidence: two independent technical vendors describing the same mechanism and naming the same consumers = the bar this investigation sets for "CONFIRMED" (§Phase 3 methodology: shared infra/IOC/mechanism *plus* an explicit vendor-stated causal link, not pattern similarity alone).
What would strengthen it further: a named downstream org's own incident report confirming execution of the poisoned package version in a build pipeline that touched production secrets.
What would falsify it for a specific org: that org's incident report stating the poisoned version was never executed (e.g., lockfile pinning prevented the auto-update) — this is a per-organization claim, not an all-or-nothing one, and should be tracked per-entity if WAIO ever ingests this incident.

No other A→B relationship in the register meets this bar. Every other candidate is demoted to §5.

---

## 5. Unconfirmed Hypotheses and Missing Evidence

**H1 — Shai-Hulud lineage as one continuing campaign (#3, #4, #5, #6) — PLAUSIBLE, WEAKENING.**
The shared mechanism (preinstall/postinstall hook payloads, credential harvesting, self-propagation via automatic version bumps) and shared naming convention suggest a single toolchain lineage. But the original toolchain was **publicly leaked on GitHub** after the May 2026 wave (per Akamai), meaning any actor could now run a "Shai-Hulud-style" attack. Treat #5 and #6 as "same tooling, actor unknown," not "same actor as #3/#4." Missing evidence: no vendor report in this register attributes #5 or #6 to the same operator as #3/#4 using non-public indicators (e.g., reused C2 infrastructure, reused signing keys, reused exfil endpoints). Falsification test already specified by the researching fork: a technical report attributing a later wave to a demonstrably different group using the leaked public toolchain would confirm the "copycat" reading over the "same actor" reading.

**H2 — Edge-device exploitation as a converging TTP (#1 Integrity Tech/Raptor Train vs. #2 Ivanti UTA0576) — COMMON TECHNIQUE, NOT A CONNECTION.**
Both target internet-facing edge/VPN appliances for durable, hard-to-monitor access. No shared infrastructure, no shared IOC, no shared or even alleged common actor across the two advisories. This is listed explicitly so a naive "both attack edge devices" detection rule is not mistaken for evidence of a real link — see §2 pattern #2 and §7's anti-pattern guidance.

**H3 — A unified "critical-infrastructure ransomware wave" (#8 Ahold Delhaize, #9 IDCF Cloud, #10 French supermarket refrigeration) — NO EVIDENCE, NOT EVEN A HYPOTHESIS WORTH TRACKING YET.**
Three different countries, three different sectors, no shared actor name, no shared IOC, and two of the three (#9, #10) have no disclosed initial-access vector at all. Explicitly recorded here so the absence of a finding is itself documented, per the mission's anti-fabrication requirement — this investigation did not look for a connection and fail to find it; it looked and found nothing to report.

**Missing evidence across the board**: none of the 11 incidents have a published, independently-confirmed IOC overlap (shared IP, domain, hash, or C2 name) with any *other* incident in this register outside the Shai-Hulud family. That absence is itself the most important data point for §7 — it argues against over-building an IOC-matching engine and for prioritizing the supply-chain-specific and time-window-correlation designs instead.

---

## 6. Attack-Chain Diagrams

**Confirmed chain (R1):**
```
keyv npm maintainer account/credential compromise
        |
        v
malicious preinstall hook shipped in keyv + dependents (400+ packages)
        |
        v   (auto-update / CI dependency resolution, ~4hr window)
        +----------------+----------------+-----------------+
        v                v                v                 v
   Deliveroo        Ornikar          OneReach      Qlik / ServiceTitan / Picsart
  (build pipeline  (build pipeline  (build pipeline   (build pipeline credential
   credential       credential       credential        exposure --
   exposure)        exposure)        exposure)         per-org CONFIRMED status
                                                         varies, not yet victim-
                                                         confirmed for all six)
```

**Weakening-attribution lineage (H1), shown with the trust break explicit:**
```
[Original Shai-Hulud toolchain, actor X]  -- 2026-05 wave (#3)
        |
        v  (toolchain LEAKED PUBLICLY on GitHub, 2026-05)
        |
        +-- any actor can now reuse this mechanism --+
        |                                            |
        v                                            v
  ChainDrop / keyv (#4, 2026-08)           tensorlake (#5, 2026-09) / @subql (#6, 2026-10)
  actor: UNKNOWN                            actor: UNKNOWN
  (mechanism-identical, NOT attributed to the same operator as #3)
```

**Where WAIO's existing pipeline sits relative to both chains today:**
```
Public incident disclosed (CISA / vendor / press)
        |
        v
Collectors (5 keyless feeds: CISA KEV, CISA Advisories, GHSA, JPCERT/CC, RIA/CERT-EE)
        |
        v
incident_normalizer -> incident_correlator (exact attack_pattern string match only)
        |
        v
critical_infra_watch.py  -- cross-country attack_pattern grouping => precursor_hypotheses
        |                     (closest existing thing to "A->B", but pattern-level only --
        |                      NOT a named-entity relationship graph like R1 above)
        v
incident_confidence.sh (0-100, auditable formula)
        |
        v
Decision Engine: decide_action(risk, confidence, multi_source)
        |                 ^-- multi_source = "≥2 WAIO MODULES agree", not "≥2 independent
        |                     real-world sources confirm a causal link" -- see GAP in §8
        v
[ RECOMMEND_CONTAINMENT reachable here on a pure global-intel record today -- see §8 ]
        |
        v
Containment Approval Gate (request/approve/reject) -- human approval required, PENDING-only
        |
        v
<<< NO EXECUTION PATH EXISTS PAST THIS POINT >>>
```

---

## 7. Recommended WAIO Detection Rules (and the Correlation Model Design — Phase 4)

This section is the Phase 4 deliverable: an evidence-based incident correlation model mapped onto WAIO's existing architecture (GLOBAL RED ALERT, Threat Landscape/Patrol Layer, SSH Exposure Monitor, SND@HOME, Takomachi Guardian, DuCoPA, PDC). All of it is **proposal only** — nothing here has been implemented as part of this investigation.

**7.1 Incident and IOC normalization (extends `incident_normalizer.sh`)**
- Current state: normalization covers incident metadata fields; cross-incident matching in `incident_correlator.sh` is an exact-match on the `attack_pattern` string only.
- Gap: no normalized, deduplicated store of concrete IOCs (IPs, domains, hashes, CVE IDs, named C2/malware-family strings) extracted per incident.
- Proposal: add an `ioc_extract` step producing a typed, deduplicated IOC table per incident (type, value, source_url, extraction_confidence). This is additive — does not change the existing state machine stages (`COLLECTED → NORMALIZED → ...`).

**7.2 Time-window correlation — occurrence date, not disclosure date**
- Gap: no sliding/temporal-proximity logic exists today; nothing distinguishes "happened recently" from "disclosed recently." The Oracle Health case (#11, §3) is the concrete counter-example: a 2025 breach disclosed in October 2026 would be wrongly clustered with genuinely-October-2026 activity by any publication-date-keyed window.
- Proposal: every incident record carries two independent dates (`occurred_at`, `disclosed_at`, both with explicit confidence/source), and the time-window correlator windows on `occurred_at` for "is this part of the same wave" questions and on `disclosed_at` only for "what should today's patrol report surface" questions. Never conflate the two.

**7.3 A→B relationship graph — named-entity edges, not pattern-similarity edges**
- Gap: `critical_infra_watch.py`'s cross-country grouping is the closest existing primitive, but it produces a *pattern-commonality* signal (paired with `alternative_explanations` and a `confidence_caveat`, correctly never a probability), not a *causal edge* between two specifically named incidents.
- Proposal: add a distinct edge type, `upstream_downstream`, created **only** when a source explicitly states the causal relationship by name (as in R1 above) — never inferred from shared `attack_pattern` alone. Each edge carries its own provenance (source URL, publication date) separately from either endpoint incident's own confidence score. This directly operationalizes the mission's CONFIRMED / PLAUSIBLE / COMMON-TECHNIQUE taxonomy used throughout §4–§5 as a stored, queryable field rather than prose-only.

**7.4 Confidence scoring with evidence provenance**
- Current state: `incident_confidence.sh` has a fully-stated, auditable 0-100 formula (source-type weight + corroboration bonus, capped +30 + staleness penalty + uncorroborated-self-report penalty) for a *single incident's* confidence.
- Gap: no separate score exists for *relationship* confidence (confidence that incident A caused/fed incident B), which is a different question from either incident's own confidence.
- Proposal: a second, equally auditable formula — e.g., base weight by evidence class (named vendor causal statement > shared non-public IOC > shared public IOC > shared technique-only), + independent-source corroboration bonus, with an explicit floor: technique-only similarity (H2-style) can never cross the PLAUSIBLE threshold, let alone CONFIRMED, no matter how many sources repeat it.

**7.5 False-positive handling**
- Proposal, directly from this investigation's own methodology: require **≥2 independent sources explicitly asserting the same named relationship** (not ≥2 sources each independently noting a similar technique) before a relationship may be marked CONFIRMED; single-source or self-claimed relationships (cf. #8's INC Ransom self-claim, #9's unattributed impact) are capped at PLAUSIBLE regardless of how severe the underlying incident is.

**7.6 Read-only SND@HOME comparison — no change needed, reuse as-is**
- `snd_crossref.py` already does exactly the right thing for this mission's constraints: pure keyword co-occurrence between the local SND@HOME snapshot and Global Patrol entities, with a mandatory `confidence_caveat` stating it is textual co-occurrence only, never causal/network/geographic proof. This pattern (global signal, local signal, explicit non-causal caveat, zero auto-action) is the template §7.3's new `upstream_downstream` edges and §7.4's relationship confidence should follow, not something to redesign.

**7.7 The one structural guardrail this investigation recommends adding in code, not just in process**
- Finding (from repo audit, §8 below): today, a Decision Engine record with `multi_source: False` — i.e., **zero local corroboration, purely global intelligence** — can already reach `RECOMMEND_CONTAINMENT` if risk is CRITICAL or (HIGH risk + HIGH confidence). The one real Phase C run had 11/74 records reach `RECOMMEND_CONTAINMENT`, **100% of them `multi_source: False`**. Human approval is still required downstream and no execution path exists, so nothing unsafe has happened — but the *rule* "a global IOC/correlation match alone must not trigger containment" is currently upheld by an accident of incomplete wiring, not by a line of code that says so.
- Proposal: add an explicit, testable guard in `decision_engine_lib.py` (or a wrapper the Containment Approval Gate calls before accepting a request) that caps the maximum reachable action at `ALERT_HUMAN` whenever `multi_source` is `False` **and** no local telemetry module (SND@HOME crossref, SSH Exposure Monitor, Shadow AI/attack_graph) independently corroborates the same entity — regardless of how high the global-source risk/confidence score is. This is the single highest-priority recommendation in this report because it converts a currently-true-by-omission safety property into a structurally-enforced, testable one.
- **IMPLEMENTED 2026-10-14 (ARCHITECTURE.md Phase 104)**: the actual guard built is slightly more precise than this original proposal — rather than gating on `multi_source` (which conflates "two global sources agree" with "one global and one local source agree"), it gates on a new, dedicated `LOCAL_SOURCE_MODULES` allowlist (`shadow_ai_monitor`, `attack_graph`, `saas_ato` — explicitly excluding `snd_home_crossref`, since that signal is itself non-causal by its own design) and re-derives trust per-record (risk ≥ MEDIUM, not stale beyond 30 days) rather than trusting bare module presence. Validated against the real 74-record Phase C input file: `RECOMMEND_CONTAINMENT` count dropped from 11 to 0 on that exact data. SSH Exposure Monitor is still not wired into the Intelligence Layer at all, so it could not be added to the allowlist without inventing an integration that doesn't exist — noted as a real, current limitation, not fixed by this phase.

---

## 8. Existing Implementation versus Missing Functionality

| Capability the mission asked about | Exists today | Gap |
|---|---|---|
| Collectors / global threat intel ingest | Yes — 5 keyless public feeds (CISA KEV, CISA Advisories, GHSA, JPCERT/CC, RIA/CERT-EE), egress-allowlisted, fail-closed | None for this mission's scope |
| Cross-incident correlation | Yes — exact `attack_pattern` string match (`incident_correlator.sh`) + cross-country grouping with precursor hypotheses (`critical_infra_watch.py`) | Pattern-level only; no IOC-level or named-causal-edge correlation (§7.1, §7.3) |
| Confidence scoring | Yes — auditable 0-100 formula, not ML (`incident_confidence.sh`) | No separate *relationship* confidence score (§7.4) |
| Time-window logic | No sliding/temporal-proximity correlator found | New design needed; must key on occurrence date not disclosure date (§7.2) |
| A→B causal graph between separate public incidents | No — `attack_graph_lib.py` is local-process-level (Shadow AI PID/port edges) only, unrelated to global incidents | New `upstream_downstream` edge type needed (§7.3) |
| SND@HOME read-only local/global comparison | Yes, and already follows the right pattern — `snd_crossref.py`, mandatory non-causal caveat, 0 signals in the one real run (SND_HOME not configured on this deployment) | None — reuse as template |
| Human approval for consequential containment | Yes — Containment Approval Gate (`containment_approval_gate.sh`/`containment_approval_lib.py`), hardened against the path-traversal class of bug in `7983f08`, 96+38 passing unit/integration checks, zero execution capability anywhere in the library | Decision Engine lacks the code-enforced global-only-ceiling guard described in §7.7 — currently a safety property of *omission*, not of *design* |
| DuCoPA / Takomachi Guardian wiring to GLOBAL RED ALERT | DuCoPA (`ducopa.sh`) is a deliberately isolated severity state machine, proven unwired by its own test suite; Takomachi (`workers/register_takomachi_agents.sh` + dashboard collector) is fleet status/dashboard visibility, not a containment executor | No connection exists between GLOBAL RED ALERT and either — appears to be intentional sequencing (commit `e6559e5`'s own message: "remain explicit, separate, later decisions"), not an oversight |
| ARCHITECTURE.md documentation currency | Phases 100–103 documented through 2026-10-12 | Phases D/E (the approval gate itself, commits `e6559e5`/`7983f08`) are shipped and tested but **not yet** written up as an ARCHITECTURE.md phase entry — docs lag code by one phase (§0 item 2) |

---

## 9. Prioritized Implementation Plan

All items below are proposals for separate, reviewable follow-up work — none were implemented in this investigation.

1. **(Highest priority, smallest change) — DONE 2026-10-14, ARCHITECTURE.md Phase 104.** Added the code-enforced global-only-ceiling guard in both `decision_engine_lib.py` (the recommendation layer) and `containment_approval_lib.py` (the approval-gate layer, which had the identical gap in its own `corroboration_satisfied()` check). 51/47/118/66/38/46/23/54/185/31 tests passed across the affected suites (0 failed), including a new real-data regression replaying the actual Phase C input file. Converts an accidental safety property into a tested, structural one.
2. **(Documentation housekeeping, zero behavior change)** Backfill ARCHITECTURE.md with Phase D/E entries for the containment approval gate, matching the existing Phase 100-103 format.
3. **(Medium priority)** Build the IOC normalization layer (§7.1) as an additive extension to `incident_normalizer.sh` — typed IOC table, no change to the existing state machine.
4. **(Medium priority)** Add the `occurred_at`/`disclosed_at` dual-date field and re-key time-window logic in the Global Patrol report generator (§7.2), using the Oracle Health case as a concrete regression-test fixture.
5. **(Lower priority, larger design surface)** Build the `upstream_downstream` relationship-graph edge type and its separate relationship-confidence formula (§7.3, §7.4) — this is the most architecturally novel piece and deserves its own design review before implementation, given it introduces a new data model (edges between incidents, not just incident records).
6. **(Explicitly not recommended now)** Scheduling `red_alert_cron.sh` via launchd. No finding in this investigation changes the existing "manual-first, explicit human approval to schedule" posture; if anything, item 1 should land first.

---

## 10. Proposed Tests and Measurable Success Criteria

For item 1 (§9) — the highest-priority recommendation:
- Unit test: a decision record with `risk=CRITICAL, confidence=95, multi_source=False, local_corroboration=None` must resolve to `ALERT_HUMAN`, not `RECOMMEND_CONTAINMENT`.
- Regression test: replay the actual Phase C dataset (74 records, 2026-10-12) through the patched decision engine and confirm the same 11 `RECOMMEND_CONTAINMENT` records from the original run now resolve to `ALERT_HUMAN` (since all 11 were `multi_source: False` in the real run) — a concrete, data-grounded success criterion rather than a synthetic one.
- Negative control: a record with genuine local corroboration (SND@HOME crossref hit or SSH Exposure Monitor match on the same entity) must still be able to reach `RECOMMEND_CONTAINMENT` — proving the guard narrows correctly rather than blocking all containment recommendations.

For item 4 (§9) — time-window correctness:
- Fixture test using the Oracle Health record (occurred 2025-01-22→2025-04-01, disclosed 2026-10-06): confirm it is **excluded** from any "last 30 days" occurrence-windowed cluster, and **included** in a disclosure-windowed "what's new this week" view — proving the two date fields are actually used for different purposes, not just stored.

For item 5 (§9) — relationship graph:
- Fixture test using the R1 ChainDrop case (§4): encoding the known six downstream organizations should produce exactly one `upstream_downstream` edge set with relationship-confidence at or above the CONFIRMED threshold; a synthetic fixture with only shared `attack_pattern` (no named causal source) must score below the PLAUSIBLE threshold — directly testing the §7.5 false-positive guard.

General measurable success criterion for the whole correlation model: **zero relationships reach CONFIRMED status in production without at least 2 independent, named, citable sources** — enforceable as a schema-level constraint (reject any CONFIRMED-flagged edge with fewer than 2 source URLs) rather than relying on reviewer discipline alone.

---

## 11. Sources, Publication Dates, and URLs

All fetched live on 2026-10-14 as part of this investigation (beyond this assistant's January 2026 knowledge cutoff; nothing below was recalled from training data):

- CISA AA26-281A, Integrity Technology Group advisory (2026-10-08) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a
- CISA alert, Ivanti Connect Secure exploited vulnerability (2026-10-13) — https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerability-ivanti-connect-secure
- Volexity, Ivanti Connect Secure zero-day chain analysis (2026-10-13) — https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
- Cloud Security Alliance, Mini Shai-Hulud research note (2026-05-17) — https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-ai-supply-chain-20260517-csa-st/
- Akamai, Mini Shai-Hulud worm returns / toolchain goes public — https://www.akamai.com/blog/security-research/mini-shai-hulud-worm-returns-goes-public
- Elastic Security Labs, ChainDrop npm supply-chain analysis (2026-08) — https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain
- StepSecurity, ChainDrop worm writeup — https://www.stepsecurity.io/blog/chaindrop-npm-worm
- StepSecurity, "5 supply chain attacks in 48 hours" (2026-10-05) — https://www.stepsecurity.io/blog/5-supply-chain-attacks-in-48-hours-why-securing-one-layer-is-not-enough
- The Hacker News, tensorlake npm package compromise (2026-10) — https://thehackernews.com/2026/10/tensorlake-npm-package-compromised-to.html
- BleepingComputer, CenterPoint Energy breach confirmation (2026-09-17) — https://www.bleepingcomputer.com/news/security/centerpoint-energy-confirms-customer-data-stolen-in-cyberattack/
- Infosecurity Magazine, Ahold Delhaize data breach (2026-10) — https://www.infosecurity-magazine.com/news/ahold-delhaize-data-breach-2m/
- CISO Series news roundup (2026-10-13) — https://cisoseries.com/cybersecurity-news-october-13-2026/
- BleepingComputer, IDCF Cloud ransomware disruption (2026-10) — https://www.bleepingcomputer.com/news/security/ransomware-attack-disrupts-japans-idcf-cloud-used-by-govt-clients/
- BleepingComputer, French supermarket refrigeration cyberattack (2026-10-13) — https://bleepingcomputer.com/news/security/cyberattack-shuts-down-refrigerators-at-french-supermarkets
- Rescana, Oracle Health/Cerner breach disclosure analysis (2026-10) — https://www.rescana.com/post/oracle-health-cerner-2026-data-breach-exposes-nearly-20-million-patient-records-across-80-u-s-hospitals

**Internal sources** (direct file inspection, this repository, 2026-10-14): `security/red_alert/*`, `security/intelligence/*`, `security/incident_learning/*`, `security/attack_graph/*`, `security/decision_engine/*`, `security/ducopa.sh`, `dashboard/collect_snd_status.sh`, `dashboard/collect_takomachi_status.sh`, `workers/register_takomachi_agents.sh`, `ARCHITECTURE.md` (Phases 100–103), `GLOBAL_THREAT_INTELLIGENCE_ASSESSMENT.md` (2026-10-09), `THREAT_LANDSCAPE_PATROL_ANALYSIS.md` (2026-10-02), commits `e6559e5`, `7983f08`, `614de4e`, `074acdf`, `7b2ef9a`, and the full test suites listed in the repo audit.
