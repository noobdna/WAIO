"""WAIO Corporate Intelligence (P1) -- public vulnerability intelligence
library: CISA KEV / NIST NVD / FIRST EPSS parsing, CVE normalization,
asset correlation and a two-axis (risk vs. evidence confidence) model.

Boundaries (see SECURITY_BOUNDARIES in ~/waio-ops/corporate-intelligence):
  - this package NEVER opens a network connection. The only network
    exit is ../ci_fetch.sh (egress_check()-gated, online opt-in only);
    tests/corporate_intel/test_boundaries.py enforces the import ban.
  - it detects and scores only. It never calls Guardian, DuCoPA,
    containment or knowledge_manager verbs.
  - Python 3.9 stdlib only.
"""

COLLECTOR_VERSION = "corporate_intel/0.1"
