# Dependency Notice Watch (W-1) — design notes

Status: **design only, no code.** Nothing here runs, nothing is scheduled, and `security/egress_allowlist.conf` is unchanged.
Merging, deploying, adding allowlist entries and scheduling each need separate human approval.

## Purpose

Watch the official status/incident feeds of external services WAIO depends on (GitHub, Cloudflare, npm, possibly Anthropic). Flag security-related notices so a human can check the affected WAIO assets. It never blocks, revokes or reconfigures anything on its own, and it sends no outbound notifications.

## Approach B: a standalone module

- Lives in `security/dependency_watch/`, separate from the Incident Learning Engine (ILE).
  - The ILE's classification and confidence scoring are built for CVE and breach reports.
  - Status notices do not fit them, and adapting them would change the ILE core.
- Reuses:
  - `security/lib.sh` `egress_check HOST PORT ...` for every fetch.
  - `security/hunt_for_red/hfr_lib.Registry.check_capture(source_id, "feed")`. Only sources whose registry status is `ALLOWED` are fetched (stop condition 1). The registry lives outside the repo, under `HFR_HOME`.
- Planned output:
  - An append-only `state/dependency_watch/notices.jsonl`.
  - Raw feed copies stored under their SHA-256.
  - A read-only dashboard collector.

## Constraints verified against this branch (2026-11-14)

1. **An unlisted destination shuts WAIO down.** `egress_check()` calls `trigger_shutdown` for a destination that is not in the allowlist, and also when the allowlist file is missing.
   The module must therefore:
   - pre-check allowlist membership read-only and exit quietly if the host is absent;
   - not be run at all until the allowlist entries are approved;
   - use `WAIO_EGRESS_ALLOWLIST` with a temporary file in tests.
2. **No redirect following.** `egress_check` only sees the first host, and `status.anthropic.com` returns 301 to `status.claude.com`. Fetch the canonical host directly and never pass `-L` to curl.
3. **Atom feeds only.** Status page `/api/` paths are disallowed by robots.txt on three of the four hosts, so the JSON API is not used.
4. No authentication, short timeouts, at most hourly polling.

## Candidate sources

All candidates are registered with `status=UNKNOWN` pending owner approval. The classification comes from the 2026-11-14 terms check; the evidence is kept privately under `HFR_HOME`.

| source_id | feed | classification |
|---|---|---|
| github-status | https://www.githubstatus.com/history.atom | retrievable |
| cloudflare-status | https://www.cloudflarestatus.com/history.atom | retrievable |
| npm-status | https://status.npmjs.org/history.atom | retrievable |
| anthropic-status | https://status.claude.com/history.atom | needs owner decision (consumer-terms scope unclear) |
| apple-security-releases | https://support.apple.com/en-us/100100 | needs owner decision (HTML only, no feed) |
| statuspage-json-api | `<status-host>/api/v2/` | not used (robots.txt) |

## Classification rules (planned)

Each notice is classified as `security`, `outage`, `maintenance` or `other` from keywords in its title and body (English and Japanese). The matched terms are recorded with the notice. For the first two weeks the module only records notices; highlighting is enabled after a human has reviewed accuracy.

## Tests (planned)

- Fabricated feeds only.
- Classifier unit tests.
- De-duplication and update handling.
- Static guards:
  - no network module imports in the parser;
  - curl is never called with `-L`;
  - no outbound notification code;
  - no ILE write paths.
- The existing ILE and HFR suites must stay green.
