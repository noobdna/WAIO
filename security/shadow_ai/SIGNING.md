# Shadow AI detector-side signing

**Status: implemented, OFF by default, no production key exists.** Turning it on
needs a key location chosen by the operator (see "Key storage", the approval
request at the end).

## What it does
With `SHADOW_AI_SIGN=1` and `SHADOW_AI_SIGNING_KEY_FILE=<path>`,
`shadow_ai_monitor.sh scan` signs every finding it prints. Each finding gets:

```json
"signing": {"scan_id": "<128-bit random hex>", "seq": 0, "signed_at": "2026-10-27T01:00:00Z"},
"wad_sig": {"alg": "hmac-sha256", "key_id": "shadow_ai", "mac": "<hex>"}
```

- `mac` = HMAC-SHA256(key, canonical JSON of the finding without `wad_sig`).
  Canonical means sorted keys, `(",", ":")` separators, `ensure_ascii=True`,
  UTF-8. The `signing` block is inside the mac.
- This is the envelope WAIO Adaptive Defense's adapter verifies (PR #215,
  `security/wad/wad_adapters.py`). A one-off check ran #215's own verifier on
  findings signed by this code: they were `verified`, and a tampered one was
  rejected.
- `inventory.json` is unchanged. Only the emitted lines are signed.
- **Failure policy:** if signing is requested but the key is unusable
  (missing, a symlink, not owned by this user, readable by group/others,
  shorter than 32 bytes), the scan still runs. Findings are emitted
  **unsigned**, with a warning on stderr and `signing=FAILED (...)` in the
  audit log. Detection never stops because of signing. A consumer that
  requires signatures (`wad.py ingest --require-signed shadow_ai`) rejects
  the unsigned output, so the failure is caught where trust is decided.

## Verification and replay protection
`shadow_ai_lib.verify_finding(obj, key, now, max_age_s=86400, max_skew_s=300, seen=None)`
returns one of these:
- `verified`
- `missing`: no `wad_sig`
- `invalid`: bad envelope, wrong `key_id`/`alg`, bad mac (any changed field),
  or a missing or malformed `signing` block
- `stale`: `signed_at` older than `max_age_s`, or further in the future than
  `max_skew_s`
- `replay`: the `(scan_id, seq)` pair is already in `seen`

The mac is checked before any field it covers is trusted. Changing
`signed_at`, `scan_id` or `seq` to freshen or disguise a replay breaks the
mac.

**WAD today (#215)** verifies the mac and `key_id`. It does not yet read the
`signing` block. Its replay protection is its own window on the signed
`detected_at`, plus duplicate/conflict detection by event identity. Making
WAD also enforce `signed_at` and `(scan_id, seq)` is a follow-up.

## What a valid signature proves, and what it does not
- **It proves** the finding was produced by someone holding the key file and
  was not changed afterwards.
- **It does not prove** which process wrote it. HMAC is symmetric: every
  verifier holds the same key and could also sign. Any process that can read
  the key file can sign too, which includes anything running as the key's
  owner, such as an AI agent session running as `masa`.
- **It is not authentication of a human.**

## Key storage (operator decision; nothing is chosen or created here)
| Option | Who can sign | Setup | Trade-offs |
|---|---|---|---|
| A. File in the user's home, e.g. `~/.config/waio/keys/shadow_ai.key` (0600, owner masa) | Anything running as masa, including agent sessions | None beyond creating the file | Simplest. Detects tampering by other users and by anything that can write the findings but not read the key. **No protection against same-user processes.** Included in Time Machine backups unless excluded. |
| B. A dedicated macOS user (e.g. `_waiodetect`) owns the key and runs the monitor (LaunchDaemon with `UserName`, key 0600 owned by that user); WAD runs as masa with read-only access to a copy of the key | That user only, plus whoever holds the verifier copy | Needs sudo: create the user, install a LaunchDaemon, set ownership | **The only option that keeps the masa account (and agents in it) from signing**, as long as WAD's copy is protected the same way. With HMAC the verifier copy can sign too; separating them fully needs asymmetric signatures (option D). |
| C. macOS Keychain item, read via `security find-generic-password` | Anything allowed by the item's ACL; by default any process as masa that can unlock the login keychain | One `security add-generic-password`; the script reads it at scan time | Encrypted at rest and not a plain file. But the `security` CLI is callable by any same-user process, and a locked keychain (e.g. after reboot, before login) makes signing fail (the unsigned fallback). LaunchAgent context is needed. |
| D. Asymmetric signature (Ed25519/P-256): private key with the detector, public key with WAD | Only the private-key holder; verifiers cannot sign | Python's standard library has no Ed25519/ECDSA. Needs the `cryptography` package (**an install**) or a native helper (Swift/CryptoKit, optionally Secure Enclave) | Removes the "verifier can forge" problem and allows hardware-backed keys. **A larger change**: a new signature format, the WAD verifier changes, and a dependency install. |
| E. Key off-host (750 or an HSM) | Wherever the key lives | Network signing path | Out of scope. Introduces a network dependency in detection, and 750 is not reachable from 800 with current keys. |

**Recommendation for review:** B if the goal is "agents running as masa
cannot forge detector output"; A only as a stepping stone, with its
limitation written down. D is the long-term design.

## Approval request
Nothing below has been done. Please choose before any of it happens:
1. A key location (A–E above).
2. Creating the key (32 random bytes, 0600). Who generates it, and where it is
   backed up, if anywhere.
3. Enabling it: `SHADOW_AI_SIGN=1` and `SHADOW_AI_SIGNING_KEY_FILE` in the
   environment of whatever runs `shadow_ai_attack_graph_cron.sh` (today the
   `com.waio.shadow-ai-attack-graph` LaunchAgent, running from the live
   checkout, which first needs a deploy of master).
4. On the WAD side: placing the verifier key at
   `$WAD_PRODUCER_KEY_DIR/shadow_ai.key` and deciding when to use
   `--require-signed shadow_ai`.
