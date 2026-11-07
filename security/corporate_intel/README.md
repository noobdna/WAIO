# WAIO Corporate Intelligence (P1, experimental)

Public vulnerability intelligence for a financial-sector risk view:
CISA KEV + NIST NVD + FIRST EPSS → CVE normalizer → correlation against
an asset inventory → **two separate axes**: risk score and evidence
confidence.

**Status: offline only.** The NVD and EPSS hosts are not in the egress
allowlist, and nothing in this directory is scheduled or wired into the
Intelligence Layer, the Decision Engine or the Dashboard.

## Boundaries

- Read-only HTTPS GET of three fixed public hosts, and only through
  `ci_fetch.sh` (`egress_check()`-gated, needs `--online` and `WAIO_CI_ONLINE=1`).
  The Python code never imports a network module (checked by a test).
- Detection and scoring only. Never calls Guardian, DuCoPA,
  containment or knowledge_manager.
- Keyless. `NVD_API_KEY` is stripped, never forwarded. All output
  passes `ci_lib/redact.py`.
- Real snapshots and reports go to `security/state/corporate_intel/`
  (gitignored). The repo holds only code, synthetic fixtures and the
  fictional bank in `synthetic/`.
- No active scanning of any organization, and no real company or
  customer data.

## Usage (offline)

```bash
M=security/corporate_intel
python3 $M/ci.py ingest --source kev  --file $M/fixtures/kev.json
for f in $M/fixtures/nvd/*.json; do python3 $M/ci.py ingest --source nvd --file "$f"; done
python3 $M/ci.py ingest --source epss --file $M/fixtures/epss.json
python3 $M/ci.py report --inventory $M/synthetic/example_bank_inventory.json
```

Set `WAIO_CI_STATE_DIR` to use a scratch state dir instead of the default.

## Model

| Axis | Inputs | Notes |
|---|---|---|
| risk 0-100 → P1..P4 | CVSS (v4.0>v3.1>v3.0>v2, Primary first) 35, likelihood (KEV=1, else √EPSS) 35, exposure 15, business impact 15, KEV ransomware +5 | KEV floor 70. Unknown inputs are scored mid-or-worst and listed in `missing`. The breakdown sums exactly to the score |
| confidence 0-100 → HIGH/MEDIUM/LOW | completeness 40, freshness 20, match precision 30, authority 10 | Never feeds into risk. Tests check both directions |

Match levels: `exact_cpe` > `vendor_product_version` > `vendor_product`
(version undecidable, or the KEV-only text fallback). A version that is
decidably outside the vulnerable range is not a match.

## Tests

```bash
bash tests/corporate_intel_test.sh        # 71 unit tests + offline E2E + real-state-untouched checks
bash tests/corporate_intel_fetch_test.sh  # ci_fetch.sh / fetch --online with fake curl + isolated egress
```
