# Attack Graph output signing and input integrity

**Status: implemented, OFF by default, no key exists.** Unset, `attack_graph.sh
build` writes exactly what it wrote before. The format and key handling are
shared with Shadow AI (`security/signing/detector_signing.py`,
`security/shadow_ai/SIGNING.md`).

## Why
WAIO Adaptive Defense's signature gate (PR #222) lets a disruptive step proceed
only on fully verified evidence. The live pipeline feeds it shadow_ai findings
and the attack_graph document. While attack_graph does not sign, any decision
that includes it can never be fully verified. Signing alone would create the
opposite problem: a graph built from **unsigned** findings would carry a valid
attack_graph signature and **launder** them. So signing comes with input
integrity.

## Variables (all off unless set)
| Variable | Effect |
|---|---|
| `ATTACK_GRAPH_INPUT_KEY_FILE` | The shadow_ai **verifier** key. Every input finding is checked (`detector_signing.verify`, key_id `shadow_ai`). Tampered (`invalid`) and replayed (`scan_id:seq` seen twice) findings are **always dropped**. |
| `ATTACK_GRAPH_REQUIRE_SIGNED_INPUT=1` | Build only from verified findings (`mode: verified_only`). Unusable input key → **exit 3, nothing written**. |
| `ATTACK_GRAPH_SIGN=1` + `ATTACK_GRAPH_SIGNING_KEY_FILE` | Sign the whole document: `signing {scan_id, seq: 0, signed_at = generated_at}` and `wad_sig {alg: hmac-sha256, key_id: attack_graph, mac}`. Unusable key → document written **unsigned**, with a warning on stderr and `signing=FAILED` in the audit log. |
| `ATTACK_GRAPH_SIGN_REQUIRED=1` | Unusable or missing signing key → **exit 3, nothing written** (the previous file is left untouched). |

When any of these is set, the document gains
`input_integrity {verified, unverified, dropped_invalid, mode, input_key_used}`.
When signed, it is **inside the mac**: hiding unverified input breaks the
signature.

Key files: a regular file (not a symlink), owned by the running user, mode 0600
or stricter, at least 32 bytes. The same rules apply as for shadow_ai.

## Trust boundaries
| Boundary | What protects it | What does not |
|---|---|---|
| shadow_ai → attack_graph (findings on stdin or a file) | Per-finding HMAC with the shadow_ai key; tampered and replayed findings dropped; `verified_only` mode | Unsigned findings when not in verified-only mode (they are counted, not hidden) |
| attack_graph → disk (`latest_graph.json`) | Document HMAC with the attack_graph key, signing block, `input_integrity` inside the mac | Anyone who can read the attack_graph key can sign a forged graph |
| disk → WAD (`wad.py ingest --attack-graph`) | PR #222: `verified` only with a trusted attack_graph key, valid mac, fresh signing block, no sig-id reuse, **and** `input_key_used: true` with `unverified: 0`; else `verified_unverified_input` (never authorizes) | Nothing beyond the key holder. HMAC is symmetric: WAD holds the same key and could sign. |

## Failure behaviour
| Situation | Default (signing requested) | `*_REQUIRED=1` |
|---|---|---|
| Signing key missing, unreadable, symlink, group/world-readable or short | Written unsigned, warning, audit `signing=FAILED` | Exit 3, nothing written |
| Input key unusable | Findings counted as unverified, warning | Exit 3, nothing written |
| Tampered or replayed input finding | Dropped, counted in `dropped_invalid` | Same |
| Non-object JSON input line | Skipped (also without any variables; it used to crash `build_graph`) | Same |

What a verifier (`detector_signing.verify`, and WAD #222) rejects, each covered by
`tests/attack_graph_signing_test.sh`: a changed field (S3, I8); another key or
key_id (S4, S5); a signature or signing block moved from another graph (P2, P3);
a malformed envelope (P4); a valid mac over a malformed signing block (P5); a
document older than 24 h or more than 5 min in the future (P6); the same graph
presented twice (P7).

## Recovery and key rotation
- **Exit 3 (required mode).** Nothing was written; the previous
  `latest_graph.json` is untouched. Fix the key file (owner, mode 0600, at least
  32 bytes, not a symlink) and run the build again. Unsigned output is never
  written as a substitute.
- **`signing=FAILED` in the audit log (non-required mode).** The graph on disk
  is unsigned and WAD treats it as unverified, so it cannot authorize anything.
  Fix the key; the next build signs again.
- **Rotation.** There is one key per key_id and no key list. Replace the key
  file on both sides (detector and `$WAD_PRODUCER_KEY_DIR/attack_graph.key`),
  then rebuild. Graphs signed with the old key become `invalid` under the new
  one (P8), and a rebuild verifies (P9). Between the two replacements, graphs
  do not verify, which fails closed. Overlapping old and new keys is not
  supported.
- **Suspected key compromise.** Rotate as above. Graphs signed before the
  rotation are not trusted after it.

## Limits (stated plainly)
- **HMAC is symmetric.** Any process that can read a key can produce valid
  signatures for that detector, including WAD and agent sessions running as
  the key owner. Detector-origin authenticity holds only as far as key storage
  keeps them out (`security/shadow_ai/SIGNING.md`, options B and D).
- **The graph is derived from shadow_ai.** Even fully verified, it is not
  independent corroboration (WAD.md §13).
- **The clock.** Freshness uses the host clock.
- **Keys.** None are generated, installed or enabled here.

## Approval needed (nothing done)
1. The key location for `attack_graph` (and `shadow_ai`). This is the same
   decision as in #219.
2. Turning it on: set the variables for the `com.waio.shadow-ai-attack-graph`
   LaunchAgent after a deploy of master, and give WAD the verifier copy at
   `$WAD_PRODUCER_KEY_DIR/attack_graph.key`.
