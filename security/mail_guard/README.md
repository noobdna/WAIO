# security/mail_guard — WAIO MAIL GUARD, 800 side (P2)

The Cloudflare Email Worker `waio-email-threat-gateway` v2 lives in a separate,
non-public repository. It decides every message at the MX and writes one
pseudonymised event per message to R2. It never connects to 800. This directory
covers everything 800 does with that:

| Piece | File | Network |
|---|---|---|
| Event pull (R2, read-only token, SigV4) | `mail_guard.sh pull` → `mail_guard.py pull` | `<account-id>.r2.cloudflarestorage.com:443` after the egress check |
| Dashboard snapshot | `dashboard/collect_mail_guard_status.sh` → `logs/mail-guard-status-latest.json` | none |
| Incident Learning feed | `security/incident_learning/collectors/mail_guard_collector.sh` (RawIncident JSONL → the existing `incident_normalizer.sh`) | none |
| Policy build (unsigned body, diff, BOZE request) | `mail_guard.py policy-build` | none |
| Policy publish (BOZE-signed → Workers KV) | `mail_guard.sh publish N` → `mail_guard.py policy-publish --execute` | `api.cloudflare.com:443` after the egress check |

State lives in `security/state/mail_guard/` (gitignored, mode 0700/0600):
`config.json`, `events.jsonl`, `cursor.json`, `last_pull.json`, and `policy/`
holding the bodies, diffs, requests and signatures, `approval-ledger.jsonl`,
`publish.log.jsonl` and `published-current.json`.

## Safety properties

- **Pull-only.** 800 has no inbound path. Events are fetched, never pushed.
- **Events are untrusted.** `sanitize_event()` keeps only whitelisted fields,
  type-checks and size-caps them, keeps domains only when they are valid ASCII
  domains, and drops everything else (including the Worker's salted hashes of
  the sender and recipient). Object keys must match `events/YYYY/MM/DD/HH/*.json`.
  Each object is capped at 64 KiB, a list response at 4 MiB, and a run at 2,000
  objects. List responses carrying a DTD are refused, and redirects are never
  followed.
- **Egress.** `mail_guard.sh` does its own read-only pre-check first: shutdown
  active, allowlist missing, or host not listed → "unavailable" (exit 3), and
  nothing is sent. The pre-check **never trips Emergency Shutdown**. The real
  DuCoPA `egress_check` (an audit-chained allow decision) runs right before the
  call, and Python refuses any host other than the one that was checked.
- **Policy writes need a human signature.** The body is canonical JSON. Its
  sha256 is bound into a BOZE request (`job_id=mailguard-policy`,
  `action=publish-v<N>`), signed off-host with `ssh-keygen -Y sign -n
  boze-approval`. `publish` does the following, in order:
  1. Verifies the signature.
  2. Checks that KV `policy:current` equals the body's `base_version`, so the
     diff the human saw is the real diff.
  3. Checks that `policy:v<N>` does not exist (versions are immutable).
  4. Consumes the nonce (one use only).
  5. Writes `policy:v<N>` and reads it back.
  6. Switches `policy:current` and reads it back.
  7. Appends to the publish log.

  `approved_by_sig_sha256` is `sha256(signature)`. Strip it and re-canonicalise
  to get the approved body hash, so anyone can audit a published document.
- **Diffs mask route destinations** (`***@domain`). The body itself contains them,
  so `security/state/` must never be copied into this public repository.
- **Validation matches the Worker.** `validate_policy()` follows the same rules
  as the Worker's `validatePolicy()`. A local cross-check of 15 cases gave 0
  mismatches. Non-ASCII domains are refused rather than converted.

## Operator setup (each step is a separate approval; none is done by this PR)

1. Copy `config.example.json` to `security/state/mail_guard/config.json` and fill
   in the account ID and KV namespace ID (32 hex characters each).
2. Keychain items (never on a command line):
   - `com.waio.mailguard.r2-access-key-id` and
     `com.waio.mailguard.r2-secret-access-key`: an R2 token, **Object Read
     only, scoped to the bucket**.
   - `com.waio.mailguard.kv-api-token`: Workers KV Storage Edit (see design
     D-5 on scoping).

   The environment variables `MAILGUARD_R2_ACCESS_KEY_ID`,
   `MAILGUARD_R2_SECRET_ACCESS_KEY` and `MAILGUARD_KV_API_TOKEN` override them.
3. Add the two commented lines from `security/egress_allowlist.conf.example` to
   the real `security/egress_allowlist.conf`.
4. Optional: install `com.waio.mail-guard-pull.plist.example` (hourly).

## Publishing a policy

```
python3 -I security/mail_guard/mail_guard.py policy-build --base-none --mode monitor \
    --add-sender-block bad.example --set-route info=dest@example.net        # first version
python3 -I security/mail_guard/mail_guard.py policy-build --mode quarantine   # later: base = last published
#   -> security/state/mail_guard/policy/policy-vN.{body.json,diff.txt,request.json}
# off-host: ssh-keygen -Y sign -f <key> -n boze-approval policy-vN.request.json
#   copy policy-vN.request.json.sig back next to the request
python3 -I security/mail_guard/mail_guard.py policy-publish --version N --allowed-signers <file>   # verify only
security/mail_guard/mail_guard.sh publish N --allowed-signers <file>                              # consume + write KV
```

Rollback via policy: build the next version with `--mode monitor` and sign and
publish it as above. The Worker picks it up within 60 s. In an emergency the
owner can also set the mode directly in the Cloudflare dashboard (design §4 R0),
or roll back with R1–R4.

## Not verified (no Cloudflare access in P2)

The R2 S3 endpoint and the KV REST calls were tested only against a local stub
and a fake. The SigV4 implementation matches the AWS reference vectors. Whether
the Keychain can be read from a LaunchAgent context is also unverified.

Tests: `tests/mail_guard_test.sh` and `tests/dashboard_mail_guard_ui_test.sh`.
