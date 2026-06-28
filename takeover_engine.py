"""
takeover_engine.py — GhostClaim Pro by Sipar Security
Core detection logic: combines DNS and HTTP results to produce a verdict.
"""

from typing import Dict, Any
from fingerprints import match_fingerprint, match_cname_only

# Verdict constants
VERDICT_VULNERABLE           = "VULNERABLE"
VERDICT_POTENTIALLY_VULN     = "POTENTIALLY_VULNERABLE"
VERDICT_SAFE                 = "SAFE"
VERDICT_ERROR                = "ERROR"

# Confidence constants
CONFIDENCE_HIGH   = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW    = "LOW"


def analyze(dns_result: Dict[str, Any], http_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze DNS and HTTP probe results to produce a takeover verdict.

    Decision logic:
        VULNERABLE           — CNAME matches known service AND HTTP body matches fingerprint
                               AND takeover_possible is True
        POTENTIALLY_VULNERABLE — CNAME matches known service but HTTP probe failed
                               or body did not match fingerprint
        SAFE                 — No CNAME, or CNAME resolves to an active resource
                               with no matching fingerprint
        ERROR                — DNS resolution failed entirely

    Args:
        dns_result:  Output dict from dns_resolver.resolve_subdomain()
        http_result: Output dict from http_prober.probe()

    Returns:
        Dict containing verdict, confidence, service, and supporting evidence.
    """
    subdomain = dns_result.get("subdomain", "unknown")

    # ── Base output structure ─────────────────────────────────────────────────
    output: Dict[str, Any] = {
        "subdomain": subdomain,
        "verdict": VERDICT_SAFE,
        "confidence": CONFIDENCE_HIGH,
        "service": None,
        "cname_chain": dns_result.get("cname_chain", []),
        "fingerprint_matched": None,
        "takeover_possible": False,
        "severity": "NONE",
        "notes": "",
    }

    # ── Case 1: DNS resolution failed entirely ────────────────────────────────
    if dns_result.get("error") and not dns_result.get("resolved"):
        output["verdict"] = VERDICT_ERROR
        output["confidence"] = CONFIDENCE_LOW
        output["notes"] = f"DNS error: {dns_result['error']}"
        return output

    # ── Case 2: No CNAME — direct A record or unresolvable ───────────────────
    final_cname = dns_result.get("final_cname")
    if not final_cname:
        output["verdict"] = VERDICT_SAFE
        output["confidence"] = CONFIDENCE_HIGH
        output["notes"] = "No CNAME record. Direct A record or non-resolvable."
        return output

    # ── Case 3: CNAME exists — check against fingerprint database ────────────
    body_snippet = http_result.get("body_snippet", "")
    http_error   = http_result.get("error")

    # Try full match: CNAME pattern + HTTP body fingerprint
    full_match = match_fingerprint(final_cname, body_snippet)

    if full_match and full_match["takeover_possible"]:
        # Strongest signal: both CNAME and body matched
        output["verdict"]              = VERDICT_VULNERABLE
        output["confidence"]           = CONFIDENCE_HIGH
        output["service"]              = full_match["service"]
        output["fingerprint_matched"]  = full_match["fingerprint"]
        output["takeover_possible"]    = True
        output["severity"]             = full_match["severity"]
        output["notes"] = (
            f"CNAME points to {full_match['service']} and HTTP response "
            f"confirms the resource is unclaimed."
        )
        return output

    # Try CNAME-only match (body didn't match or probe failed)
    cname_match = match_cname_only(final_cname)

    if cname_match:
        if http_error:
            # Probe failed — cannot confirm, but CNAME is suspicious
            output["verdict"]   = VERDICT_POTENTIALLY_VULN
            output["confidence"] = CONFIDENCE_MEDIUM
            output["service"]   = cname_match["service"]
            output["severity"]  = cname_match["severity"]
            output["notes"] = (
                f"CNAME points to {cname_match['service']} but HTTP probe failed: "
                f"{http_error}. Manual verification required."
            )
        elif dns_result.get("nxdomain"):
            # CNAME points to NXDOMAIN — dangling, high risk
            output["verdict"]   = VERDICT_POTENTIALLY_VULN
            output["confidence"] = CONFIDENCE_HIGH
            output["service"]   = cname_match["service"]
            output["severity"]  = cname_match["severity"]
            output["notes"] = (
                f"CNAME points to {cname_match['service']} which returns NXDOMAIN. "
                f"Resource may be claimable. HTTP fingerprint did not match."
            )
        else:
            # CNAME matched service but body fingerprint did not match
            output["verdict"]   = VERDICT_POTENTIALLY_VULN
            output["confidence"] = CONFIDENCE_LOW
            output["service"]   = cname_match["service"]
            output["severity"]  = cname_match["severity"]
            output["notes"] = (
                f"CNAME points to {cname_match['service']} but response body "
                f"did not match the expected fingerprint. Service may be active."
            )
        return output

    # ── Case 4: CNAME exists but no known service matched → SAFE ─────────────
    output["verdict"]   = VERDICT_SAFE
    output["confidence"] = CONFIDENCE_HIGH
    output["notes"] = (
        f"CNAME resolves to {final_cname} which is not in the vulnerable service database."
    )
    return output


def summarize(findings: list) -> Dict[str, int]:
    """
    Produce a count summary of verdict categories from a list of findings.

    Args:
        findings: List of dicts returned by analyze()

    Returns:
        Dict with counts for total, vulnerable, potentially_vulnerable, safe, error.
    """
    summary = {
        "total": len(findings),
        "vulnerable": 0,
        "potentially_vulnerable": 0,
        "safe": 0,
        "error": 0,
    }

    for finding in findings:
        verdict = finding.get("verdict", "")
        if verdict == VERDICT_VULNERABLE:
            summary["vulnerable"] += 1
        elif verdict == VERDICT_POTENTIALLY_VULN:
            summary["potentially_vulnerable"] += 1
        elif verdict == VERDICT_SAFE:
            summary["safe"] += 1
        elif verdict == VERDICT_ERROR:
            summary["error"] += 1

    return summary
