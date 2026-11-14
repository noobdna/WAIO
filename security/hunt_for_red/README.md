# HUNT FOR RED — P1: Evidence Ledger

HUNT FOR RED (HFR) is a case-and-value layer on top of the Incident Learning Engine (D-1). This directory holds only code and fabricated examples. **Case data and the real Source Registry live only under `HFR_HOME`** (default `~/waio-ops/hunt-for-red`). The library refuses an `HFR_HOME` inside any git working tree (D-2).

P1 scope: append-only, hash-chained per-case ledger and Source Registry gate. There is no fetching (P3), no scoring (P5), no reports (P6) and no scheduling.

## Records

| type | id letter | purpose |
|---|---|---|
| `case` | K | scope, human approver, cost cap, linked Incident Learning candidate ids (read-only) |
| `capture` | R | one stored source document: `raw/<sha256>`, read-only, after redaction |
| `claim` | C | one statement: FACT / HYPOTHESIS / UNKNOWN, supports / contradicts / alternatives |
| `ioc` | I | indicator, stored **defanged only** |
| `cost` | X | measured minutes / yen |
| `event` | E | OPENED / HELD / STOPPED / SCALED_DOWN / RESUMED / CLOSED |

Enforced rules:
- A capture needs an approved case (`approved_by: human:...`) and a registry source with `status=ALLOWED` and `collect`/`store_raw` of `yes` or `conditional`.
- `method` must be one of the passive methods (D-3): `feed`, `manual_browse`, `web_search_result`, `owner_provided`. Connecting to the investigated infrastructure is not a method here.
- A claim can be FACT only with a primary capture in `supports` and nothing in `contradicts`. HYPOTHESIS needs a primary or secondary capture and an alternative explanation. A claim backed only by `directive_only` captures is UNKNOWN.
- Every claim carries `attribution: true|false`.
- Corrections are new records with `supersedes`. Nothing is edited or deleted.
- `redact_json_keys` from the registry are removed before storage, and the original is kept only as `redaction.original_sha256`. If a personal-looking key (`login`, `email`, `user`, `avatar_url`, ...) is left afterwards, the capture is refused.
- HELD / STOPPED / CLOSED block new captures. RESUMED needs `approved_by: human:...`. Exceeding the case cost cap appends HELD automatically (stop condition 6).

## Known limits

- The hash chain is **unkeyed**. It detects edits, deleted lines and reordering, but not a consistent rewrite of the whole file. Keying it needs a decision on where the key is kept.
- `approved_by: human:...` is recorded, not proven. An agent with write access could forge it. Enforcing human-only approval is open decision D-7.
- Personal-field detection works on JSON only. A source with redaction rules refuses non-JSON content.
- Locking uses `fcntl.flock` on `cases/<id>/.ledger.lock` (single host). It does not use `security/incident_learning/lock.sh`, so it is not affected by the mkdir-lock race fixed in #226.

## Use

```
export HFR_HOME=~/waio-ops/hunt-for-red
python3 security/hunt_for_red/hfr.py case-open HFR-0001 --agent claude@800 --title ... --scope-json '{...}' \
    --approved-by human:owner --approved-at 2026-01-01T00:00:00Z --approval-ref ... --cap-minutes 600 --cap-yen 0
python3 security/hunt_for_red/hfr.py capture HFR-0001 --agent claude@800 --file advisory.json --source-id cisa-kev \
    --method feed --url https://... --fetched-at ... --content-type application/json --verification primary
python3 security/hunt_for_red/hfr.py verify HFR-0001
```

Tests: `tests/hunt_for_red_test.sh` (fabricated data and a temporary `HFR_HOME` only).
