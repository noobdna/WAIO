"""security/yashi/yashi_lib.py -- YASHI Defense Learning Mode: turns
records the Incident Learning Engine has ALREADY collected, normalized,
verified and scored (security/state/incident_learning/candidates/*.json)
into structured scam/fraud defense cases, and closes the loop the
existing pipeline stops short of:

    (existing) COLLECT -> NORMALIZE -> VERIFY -> ANALYZE -> SCORE
    (this)     -> CLASSIFY -> EXTRACT TTPs -> MAP DETECTIONS
               -> GENERATE TESTS -> VALIDATE -> PROPOSE DEFENSE UPDATES

Each case has the seven sections the operator asked for (summary and
source / technique and assets / indicators and detection / defensive
rules and responses / false-positive risk and confidence / tests /
lessons and uncertainties), and every section keeps CONFIRMED facts
(copied verbatim from the pipeline record, with provenance) apart from
HYPOTHESES (this module's own keyword classification).

Hard rules, enforced here:
  - read-only on its input: no network, no subprocess, no eval/exec;
    candidate records are never modified (the CLI writes only to its
    own output directory);
  - no perpetrator attribution: no field for an actor exists, and the
    classifier never emits one;
  - nothing is deployed. Every proposal is PROPOSED_REQUIRES_HUMAN_APPROVAL
    and names the existing WAIO detector it would extend; there is no
    code path that edits a detector, a config or an allowlist;
  - generated tests are synthetic (example.* / .invalid / .test only)
    and are validated by running the REAL detector
    (security/mail_forensics/mail_forensics_lib.py) on them in memory.

Provenance of the technique catalog below: every ATT&CK ID was checked
by hand against attack.mitre.org on 2026-10-20, when ATT&CK v19
(2026-04-28) was current. The results are in ATTACK_VERIFIED. That check
found T1656 "Impersonation" REVOKED in v19 and replaced by
T1684.001 "Social Engineering: Impersonation" (see ATTACK_REVOKED).
This module never fetches anything itself; a case reports
`catalog_reference_verified: true` only when every ID it cites is in
ATTACK_VERIFIED.
"""

import email
import email.policy
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "mail_forensics"))
import mail_forensics_lib as mf  # noqa: E402  (real detector, used for VALIDATE)


CATALOG_VERSION = "2026-10-20.2"

ATTACK_VERIFIED_AT = "2026-10-20"
ATTACK_VERIFIED_VERSION = "v19"
# id -> name exactly as shown on attack.mitre.org at ATTACK_VERIFIED_AT.
ATTACK_VERIFIED = {
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1111": "Multi-Factor Authentication Interception",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1539": "Steal Web Session Cookie",
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1586": "Compromise Accounts",
    "T1588.007": "Obtain Capabilities: Artificial Intelligence",
    "T1589": "Gather Victim Identity Information",
    "T1589.002": "Gather Victim Identity Information: Email Addresses",
    "T1598": "Phishing for Information",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1684": "Social Engineering",
    "T1684.001": "Social Engineering: Impersonation",
    "T1684.002": "Social Engineering: Email Spoofing",
}
# Revoked id -> replacement (v19 release notes, 2026-04-28).
ATTACK_REVOKED = {"T1656": "T1684.001"}

# Statuses the pipeline has let through its own confidence threshold.
DEFAULT_INPUT_STATUSES = ("CANDIDATE", "HOLD", "APPROVED", "PROMOTED")

# Collectors whose output is synthetic by design; never learned from.
MOCK_SOURCE_RE = re.compile(r"^mock_")

SOURCE_RELIABILITY = {"cert": "HIGH", "vendor_advisory": "HIGH", "news": "MEDIUM"}


def source_reliability(rec):
    """-> (level, note). AI-compiled research records are secondary."""
    if (rec.get("source") or "").startswith("claude_research"):
        return "SECONDARY", "AI-compiled research summary; verify against source_url before relying on it"
    return SOURCE_RELIABILITY.get(rec.get("source_type"), "LOW"), ""

# technique id -> definition. `detectors` name detectors that EXIST in
# this repo today; an empty list is a recorded detection GAP.
# `fixture` names a synthetic mail generator below (or None).
TECHNIQUES = {
    "YT-PHISH-LINK": {
        "category": "phishing_impersonation",
        "name": "Phishing link that shows one destination and goes to another",
        "attack_ids": ["T1566.002", "T1204.001"],
        "keywords": [r"phishing", r"malicious (?:link|url)", r"spear-?phishing link", r"fake login"],
        "detectors": ["mail_forensics:HTML_ANCHOR_TEXT_MISMATCH", "mail_forensics:URL_DOMAIN_NOT_ALIGNED"],
        "fp_risks": ["Marketing mail routinely links through click-tracking domains (URL_DOMAIN_NOT_ALIGNED alone is weak)."],
        "fixture": "anchor_mismatch",
        "expect": ["HTML_ANCHOR_TEXT_MISMATCH"],
    },
    "YT-IMPERSONATION": {
        "category": "phishing_impersonation",
        "name": "Brand / authority impersonation in the sender identity",
        "attack_ids": ["T1684.001", "T1566"],
        "keywords": [r"impersonat\w*", r"pos(?:e|ing) as", r"spoofed (?:brand|sender)", r"なりすまし"],
        "detectors": ["mail_forensics:DISPLAY_NAME_DOMAIN_MISMATCH", "mail_forensics:REPLY_TO_DOMAIN_MISMATCH"],
        "fp_risks": ["Legitimate senders using a third-party mailer (ESP) can show a display name that differs from the envelope domain."],
        "fixture": "display_name_spoof",
        "expect": ["DISPLAY_NAME_DOMAIN_MISMATCH", "REPLY_TO_DOMAIN_MISMATCH"],
    },
    "YT-SPOOF-AUTH": {
        "category": "email_spoofing_auth",
        "name": "Header From spoofing visible as SPF/DKIM/DMARC failure",
        "attack_ids": ["T1684.002", "T1566"],
        "keywords": [r"e-?mail spoof\w*", r"spoofed (?:e-?mail|sender|domain|from)", r"(?:sender|domain|display.name) spoofing",
                     r"\bdmarc\b", r"\bdkim\b", r"\bspf (?:record|fail\w*|check)", r"email authentication"],
        # CWE-290 "authentication bypass by spoofing" is a software flaw, not mail spoofing.
        "exclude": [r"bypass by spoofing", r"spoofing vulnerability"],
        "detectors": ["mail_forensics:DMARC_FAIL", "mail_forensics:SPF_FAIL", "mail_forensics:DKIM_NOT_ALIGNED"],
        "fp_risks": ["Mailing lists and forwarders break SPF/DKIM; check ARC and the trusted first hop before acting."],
        "fixture": "dmarc_fail",
        "expect": ["DMARC_FAIL", "SPF_FAIL"],
    },
    "YT-FRAUD-DOMAIN": {
        "category": "fraudulent_domain_url",
        "name": "Look-alike or freshly registered domain used as lure infrastructure",
        "attack_ids": ["T1583.001"],
        "keywords": [r"typosquat\w*", r"look-?alike domain", r"newly registered domain", r"fraudulent (?:site|website|domain)", r"fake (?:site|website|shop)"],
        "detectors": ["mail_forensics:URL_DOMAIN_NOT_ALIGNED"],
        "fp_risks": ["Domain age is not checked by any WAIO detector yet (no WHOIS/RDAP lookup by design) -- detection is alignment-only."],
        "fixture": "lookalike_url",
        "expect": ["URL_DOMAIN_NOT_ALIGNED"],
    },
    "YT-CRED-ATO": {
        "category": "credential_theft_ato",
        "name": "Credential theft leading to account takeover",
        "attack_ids": ["T1078", "T1110", "T1539", "T1586"],
        "keywords": [r"credential (?:theft|harvest\w*|stuffing)", r"account takeover", r"stolen credentials", r"session (?:token|cookie) theft", r"password spray\w*", r"brute.?force"],
        "detectors": ["saas_ato:impossible_travel_signin", "saas_ato:new_forwarding_rule", "saas_ato:oauth_grant", "saas_ato:mass_send"],
        "fp_risks": ["VPN egress changes and travel produce impossible-travel signals for legitimate users."],
        "fixture": None,
        "expect": [],
    },
    "YT-MFA-FATIGUE": {
        "category": "credential_theft_ato",
        "name": "MFA interception or push-fatigue",
        "attack_ids": ["T1621", "T1111"],
        "keywords": [r"mfa (?:fatigue|bombing|bypass)", r"push (?:fatigue|bombing)", r"adversary-in-the-middle", r"\baitm\b", r"one-time (?:password|code) (?:theft|relay)"],
        "detectors": [],
        "fp_risks": ["No MFA telemetry source is wired into WAIO; any rule here would be speculative."],
        "fixture": None,
        "expect": [],
    },
    "YT-PII-EXPOSURE": {
        "category": "pii_exposure_identity_abuse",
        "name": "Personal-information exposure enabling targeted fraud",
        "attack_ids": ["T1589", "T1589.002"],
        "keywords": [r"personal (?:information|data) (?:leak|exposure|breach)", r"data breach", r"\bpii\b", r"identity (?:theft|fraud)", r"個人情報", r"漏え?い",
                     r"expos\w*.{0,60}(?:e-?mail address\w*|personal data|customer data|home address\w*)",
                     r"(?:social security|cpr|national id\w*|passport) numbers?"],
        "detectors": [],
        "fp_risks": ["Exposure reports rarely say which addresses leaked; mapping one to a local alias needs evidence, not inference."],
        "interface": "gap_detectors:pii_exposure_notice",
        "fixture": None,
        "expect": [],
    },
    "YT-SOCIAL-ENG": {
        "category": "social_engineering",
        "name": "Pretexting: urgency, payment or support-desk lures",
        "attack_ids": ["T1598", "T1684.001"],
        "keywords": [r"social engineering", r"pretext\w*", r"business email compromise", r"\bbec\b", r"help ?desk", r"vishing", r"smishing", r"tech support scam"],
        "detectors": ["mail_forensics:REPLY_TO_DOMAIN_MISMATCH"],
        "fp_risks": ["Urgency wording alone is common in legitimate billing mail; never score on wording only."],
        "fixture": "reply_to_redirect",
        "expect": ["REPLY_TO_DOMAIN_MISMATCH"],
    },
    "YT-MAL-ATTACH": {
        "category": "malicious_attachment",
        "name": "Malicious attachment (executable, script, macro document, archive)",
        "attack_ids": ["T1566.001", "T1204.002"],
        "keywords": [r"malicious attachment", r"spear-?phishing attachment", r"\bmacro\b", r"\.lnk\b", r"\biso\b file", r"html smuggling", r"malware.{0,20}attach"],
        "detectors": ["mail_forensics:RISKY_ATTACHMENT"],
        "fp_risks": ["Business mail legitimately carries .zip/.xlsm; the extension list is a review trigger, not a verdict."],
        "fixture": "risky_attachment",
        "expect": ["RISKY_ATTACHMENT"],
    },
    "YT-AI-SCAM": {
        "category": "ai_enabled_scam",
        "name": "AI-enabled scam (deepfake voice/video, LLM-written lures)",
        "attack_ids": ["T1684.001", "T1588.007"],
        "keywords": [r"deepfake", r"voice clon\w*", r"\bai-?(?:generated|enabled|powered)\b", r"\bllm\b", r"generative ai", r"synthetic (?:voice|media)"],
        # An AI term alone is not a scam: an accidental exposure caused by
        # AI-written code (2026-10-20 check of WAIO-INTEL-2026-012) or an
        # AI-assisted intrusion must not land here. Require deception context.
        "require": [r"\bscam\w*", r"\bfraud\w*", r"impersonat\w*", r"deceiv\w*", r"swindl\w*", r"詐欺", r"なりすまし"],
        "detectors": [],
        "fp_risks": ["No WAIO detector can tell AI-written text from human text; do not build a rule on that claim."],
        "interface": "gap_detectors:ai_scam_signal",
        "fixture": None,
        "expect": [],
    },
}


# --- CLASSIFY / EXTRACT TTPs ------------------------------------------

# Fields describing what was OBSERVED. potential_abuse_paths and
# exposure_categories are the normalizer's own guesses about what COULD
# follow, so classifying on them would turn a guess into a technique.
OBSERVED_LIST_FIELDS = ("attack_vector_list", "ttp_list", "impact_list")


def record_text(rec):
    parts = [rec.get("raw_text", ""), rec.get("attack_pattern", ""), rec.get("incident_type", "")]
    for k in OBSERVED_LIST_FIELDS:
        parts.extend(str(x) for x in rec.get(k) or [])
    return " ".join(p for p in parts if p)


def classify(rec):
    """-> [{technique, category, matched_by, evidence}], HYPOTHESES only:
    keyword or ATT&CK-id overlap with the record's own fields."""
    text = record_text(rec)
    low = text.lower()
    rec_ttps = set(re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", " ".join(str(x) for x in rec.get("ttp_list") or []) + " " + text))
    out = []
    for tid, t in TECHNIQUES.items():
        if t.get("require") and not any(re.search(r, low, re.I) for r in t["require"]):
            continue
        hit = None
        for kw in t["keywords"]:
            for m in re.finditer(kw, low, re.I):
                s = max(0, m.start() - 60)
                ctx = text[s:m.end() + 60]
                if any(re.search(x, ctx, re.I) for x in t.get("exclude", ())):
                    continue
                hit = {"matched_by": "keyword:" + kw, "evidence": ctx}
                break
            if hit:
                break
        if not hit:
            shared = sorted(rec_ttps & set(t["attack_ids"]))
            if shared:
                hit = {"matched_by": "attack_id:" + ",".join(shared), "evidence": ",".join(shared)}
        if hit:
            out.append(dict(technique=tid, category=t["category"], **hit))
    return out


def dedupe_key(rec):
    """Same incident seen twice (re-collected, or by two collectors)."""
    cves = sorted(set(rec.get("cve_list") or []))
    if cves:
        return "cve:" + ",".join(cves)
    url = (rec.get("source_url") or "").lower().rstrip("/")
    url = re.sub(r"^https?://(www\.)?", "", url)
    return "url:" + url if url else "id:" + rec.get("id", "")


# --- GENERATE TESTS / VALIDATE -----------------------------------------

_BASE = (
    "Authentication-Results: mx.cloudflare.net; spf={spf} smtp.mailfrom={mfrom}; "
    "dkim={dkim} header.d={dkimd}; dmarc={dmarc} header.from={fromdom}\n"
    "Received: from relay.example.test (relay.example.test [192.0.2.30]) by mx.cloudflare.net; Mon, 19 Oct 2026 00:00:00 +0000\n"
    "From: {fromhdr}\n{extra}To: user@example.org\nSubject: test\n"
    "Date: Mon, 19 Oct 2026 00:00:00 +0000\nMessage-ID: <t1@{fromdom}>\nMIME-Version: 1.0\n"
)


def _mail(fromhdr="Example <info@example.com>", fromdom="example.com", spf="pass", dkim="pass", dmarc="pass",
          extra="", body_html=None, body_text="hello", attachment=None):
    head = _BASE.format(spf=spf, mfrom="b@" + fromdom, dkim=dkim, dkimd=fromdom, dmarc=dmarc,
                        fromdom=fromdom, fromhdr=fromhdr, extra=extra)
    if attachment:
        return (head + 'Content-Type: multipart/mixed; boundary="Y"\n\n--Y\nContent-Type: text/plain\n\n'
                + body_text + "\n--Y\nContent-Type: application/octet-stream\n"
                + 'Content-Disposition: attachment; filename="%s"\nContent-Transfer-Encoding: base64\n\naGVsbG8=\n--Y--\n' % attachment)
    if body_html is not None:
        return head + "Content-Type: text/html; charset=utf-8\n\n" + body_html + "\n"
    return head + "Content-Type: text/plain; charset=utf-8\n\n" + body_text + "\n"


# fixture name -> (positive message, negative message). The negative is
# the closest LEGITIMATE look-alike: it must NOT raise the expected codes.
FIXTURES = {
    "anchor_mismatch": (
        lambda: _mail(body_html='<a href="https://login.lure.test/x">https://www.example.com/account</a>'),
        lambda: _mail(body_html='<a href="https://www.example.com/account">https://www.example.com/account</a>'),
    ),
    "display_name_spoof": (
        lambda: _mail(fromhdr='"www.bank.example.net" <notice@lure.test>', fromdom="lure.test",
                      extra="Reply-To: <collect@reply.invalid>\n"),
        lambda: _mail(fromhdr='"Example Support" <support@example.com>', extra="Reply-To: <help@example.com>\n"),
    ),
    "dmarc_fail": (
        lambda: _mail(spf="fail", dkim="none", dmarc="fail"),
        lambda: _mail(),
    ),
    "lookalike_url": (
        lambda: _mail(body_text="Verify at https://examp1e-com.lure.test/verify"),
        lambda: _mail(body_text="Verify at https://www.example.com/verify"),
    ),
    "reply_to_redirect": (
        lambda: _mail(extra="Reply-To: <ceo-urgent@reply.invalid>\n", body_text="Please wire the payment today."),
        lambda: _mail(extra="Reply-To: <billing@example.com>\n", body_text="Your invoice is attached."),
    ),
    "risky_attachment": (
        lambda: _mail(attachment="invoice.pdf.lnk"),
        lambda: _mail(attachment="invoice.pdf"),
    ),
}


def validate_technique(tid):
    """Run the REAL detector on the technique's synthetic positive and
    negative fixtures. -> dict with status PASS / FAIL / NO_FIXTURE."""
    t = TECHNIQUES[tid]
    if not t["fixture"]:
        return {"technique": tid, "status": "NO_FIXTURE", "detail": "no synthetic test possible with current WAIO detectors"}
    pos_fn, neg_fn = FIXTURES[t["fixture"]]
    pos = {i["code"] for i in mf.analyze_message(email.message_from_string(pos_fn(), policy=email.policy.default))["indicators"]}
    neg = {i["code"] for i in mf.analyze_message(email.message_from_string(neg_fn(), policy=email.policy.default))["indicators"]}
    missing = sorted(set(t["expect"]) - pos)
    false_pos = sorted(set(t["expect"]) & neg)
    return {
        "technique": tid, "fixture": t["fixture"],
        "status": "PASS" if not missing and not false_pos else "FAIL",
        "positive_codes": sorted(pos), "negative_codes": sorted(neg),
        "missing_on_positive": missing, "raised_on_negative": false_pos,
    }


# --- CASES / PROPOSALS ------------------------------------------------

def catalog_verified(techs):
    ids = {i for t in techs for i in TECHNIQUES[t]["attack_ids"]}
    return bool(ids) and ids <= set(ATTACK_VERIFIED) and not ids & set(ATTACK_REVOKED)


def build_case(rec, matches, validations, record_sha256, known_techniques, verification=None):
    techs = [m["technique"] for m in matches]
    # Copy: the binding fields below are per case, not written back to the shared map.
    verification = dict(verification or {"status": "NOT_CHECKED"})
    uncertainties = []
    if verification["status"] != "NOT_CHECKED":
        # A hand check is evidence about one version of the record. Bind it by
        # record_sha256 so a later pipeline rewrite cannot inherit the old verdict.
        checked_sha = verification.get("record_sha256")
        if not checked_sha:
            verification["binding"] = "UNBOUND"
            uncertainties.append("source check has no record_sha256; the record may have changed since it was checked")
        elif checked_sha != record_sha256:
            verification["binding"] = "STALE"
            verification["status_at_check"] = verification["status"]
            verification["status"] = "STALE"
            uncertainties.append("source check was made against a different version of the record (record_sha256 changed); re-check needed")
        else:
            verification["binding"] = "BOUND"
        if verification.get("checked_url") and rec.get("source_url") and verification["checked_url"] != rec["source_url"]:
            verification["checked_url_matches_record"] = False
            uncertainties.append("source check used a different URL than the record's source_url")
    if verification["status"] == "NOT_CHECKED":
        uncertainties.append("record not checked against its original source")
    elif verification["status"] == "SOURCE_UNREACHABLE":
        uncertainties.append("original source could not be retrieved (%s); claims rest on the record alone" % verification.get("note", ""))
    for d in verification.get("discrepancies", []):
        uncertainties.append("source check: " + d)
    if rec.get("evidence_self_reported_uncorroborated"):
        uncertainties.append("source is self-reported and uncorroborated")
    if not rec.get("corroborating_sources"):
        uncertainties.append("no corroborating source recorded by the pipeline")
    if rec.get("occurred_at") in (None, "", "不明"):
        uncertainties.append("occurrence date unknown")
    uncertainties.append("technique classification is keyword-based (hypothesis), not analyst-confirmed")
    reliability, rel_note = source_reliability(rec)
    if rel_note:
        uncertainties.append(rel_note)
    return {
        "case_id": "YASHI-" + rec.get("id", ""),
        "dedupe_key": dedupe_key(rec),
        "1_summary_and_source": {
            "confirmed": {
                "incident_id": rec.get("id"), "summary": (rec.get("raw_text") or "")[:600],
                "source": rec.get("source"), "source_type": rec.get("source_type"),
                "source_url": rec.get("source_url"), "published_at": rec.get("published_at") or "unknown",
                "collected_at": rec.get("collected_at"),
            },
            "source_reliability": reliability,
            "provenance": {"pipeline_status": rec.get("status"), "record_sha256": record_sha256,
                           "last_verified_at": rec.get("updated_at"), "catalog_version": CATALOG_VERSION,
                           "catalog_reference_verified": catalog_verified(techs),
                           "attack_verified_at": ATTACK_VERIFIED_AT, "attack_version": ATTACK_VERIFIED_VERSION},
            "source_verification": verification,
        },
        "2_technique_and_assets": {
            "confirmed": {"incident_type": rec.get("incident_type"), "affected_sector": rec.get("affected_sector"),
                          "cve_list": rec.get("cve_list") or [], "record_ttp_list": rec.get("ttp_list") or []},
            "hypotheses": [{"technique": m["technique"], "category": m["category"],
                            "attack_ids": TECHNIQUES[m["technique"]]["attack_ids"],
                            "matched_by": m["matched_by"], "evidence": m["evidence"],
                            "novelty": "previously_known" if m["technique"] in known_techniques else "newly_observed"}
                           for m in matches],
            # The pipeline's own guesses about what could follow; recorded, never classified on.
            "pipeline_potential_abuse_paths": rec.get("potential_abuse_paths") or [],
        },
        "3_indicators_and_detection": {
            "confirmed": {"ioc_list": rec.get("ioc_list") or [], "detection_points": rec.get("detection_points") or []},
            "detection_opportunities": sorted({d for t in techs for d in TECHNIQUES[t]["detectors"]}),
            "detection_gaps": sorted(t for t in techs if not TECHNIQUES[t]["detectors"]),
        },
        "4_defensive_rules_and_responses": {
            "confirmed": {"mitigations": rec.get("mitigations") or [], "defensive_priorities": rec.get("defensive_priorities") or []},
            "recommended_response": "HUMAN_REVIEW",
            "automatic_blocking": False,
        },
        "5_false_positive_risk_and_confidence": {
            "pipeline_confidence_score": rec.get("confidence_score"),
            "fp_risks": sorted({r for t in techs for r in TECHNIQUES[t]["fp_risks"]}),
            "classification_confidence": "LOW" if all(m["matched_by"].startswith("keyword:") for m in matches) else "MEDIUM",
        },
        "6_tests": [validations[t] for t in techs],
        "7_lessons_and_uncertainties": {
            "lessons": ["%s: covered by %s" % (t, ", ".join(TECHNIQUES[t]["detectors"])) if TECHNIQUES[t]["detectors"]
                        else "%s: no WAIO detector covers this today" % t for t in techs],
            "uncertainties": uncertainties,
        },
        # Deliberately absent: any perpetrator / attribution field.
    }


def propose(cases, validations):
    """One proposal per observed technique: EXTEND (detector exists and
    its fixture validated), FIX_DETECTOR (fixture failed), or GAP."""
    seen = {}
    for c in cases:
        for h in c["2_technique_and_assets"]["hypotheses"]:
            seen.setdefault(h["technique"], []).append(c["case_id"])
    proposals = []
    for tid in sorted(seen):
        t, v = TECHNIQUES[tid], validations[tid]
        if not t["detectors"]:
            kind = "GAP_INTERFACE_DEFINED" if t.get("interface") else "GAP"
        elif v["status"] == "FAIL":
            kind = "FIX_DETECTOR"
        else:
            kind = "EXTEND"
        proposals.append({
            "technique": tid, "category": t["category"], "kind": kind,
            "detectors": t["detectors"], "validation": v["status"],
            "interface": t.get("interface"),
            # A defined interface is not a detector: nothing feeds it yet.
            "production_ready": bool(t["detectors"]) and v["status"] == "PASS",
            "supporting_cases": sorted(set(seen[tid]))[:20], "supporting_case_count": len(set(seen[tid])),
            "status": "PROPOSED_REQUIRES_HUMAN_APPROVAL",
        })
    return proposals


def learn(records, known_techniques=(), verifications=None):
    """records: [(record_dict, record_sha256)] -> result dict.
    Deduplicates on dedupe_key (keeps the most recently updated)."""
    validations = {tid: validate_technique(tid) for tid in TECHNIQUES}
    best = {}
    excluded_mock = 0
    for rec, sha in records:
        if rec.get("status") not in DEFAULT_INPUT_STATUSES:
            continue
        if MOCK_SOURCE_RE.match(rec.get("source") or ""):
            excluded_mock += 1
            continue
        k = dedupe_key(rec)
        if k not in best or (rec.get("updated_at") or "") > (best[k][0].get("updated_at") or ""):
            best[k] = (rec, sha)
    known = set(known_techniques)
    cases = []
    for k in sorted(best):
        rec, sha = best[k]
        matches = classify(rec)
        if matches:
            cases.append(build_case(rec, matches, validations, sha, known, (verifications or {}).get(rec.get("id"))))
    observed = sorted({h["technique"] for c in cases for h in c["2_technique_and_assets"]["hypotheses"]})
    return {
        "catalog_version": CATALOG_VERSION,
        "input_records": len(records),
        "excluded_mock": excluded_mock,
        "eligible_after_dedupe": len(best),
        "cases": cases,
        "validations": validations,
        "proposals": propose(cases, validations),
        "observed_techniques": observed,
        "newly_observed_techniques": sorted(set(observed) - known),
    }
