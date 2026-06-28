"""
fingerprints.py — GhostClaim Free by Sipar Security
Vulnerable service fingerprint database (10 services).
Upgrade to GhostClaim Pro for 30+ service fingerprints.
Based on the EdOverflow/can-i-take-over-xyz community list.
"""

from typing import List, Dict, Any

FINGERPRINTS: List[Dict[str, Any]] = [
    {
        "service": "GitHub Pages",
        "cname_pattern": "github.io",
        "fingerprint": "There isn't a GitHub Pages site here",
        "takeover_possible": True,
        "severity": "HIGH"
    },
    {
        "service": "Heroku",
        "cname_pattern": "herokuapp.com",
        "fingerprint": "No such app",
        "takeover_possible": True,
        "severity": "HIGH"
    },
    {
        "service": "Vercel",
        "cname_pattern": "vercel.app",
        "fingerprint": "The deployment could not be found",
        "takeover_possible": True,
        "severity": "HIGH"
    },
    {
        "service": "Netlify",
        "cname_pattern": "netlify.app",
        "fingerprint": "Not Found - Request ID",
        "takeover_possible": True,
        "severity": "HIGH"
    },
    {
        "service": "AWS S3",
        "cname_pattern": "s3.amazonaws.com",
        "fingerprint": "NoSuchBucket",
        "takeover_possible": True,
        "severity": "HIGH"
    },
    {
        "service": "Azure App Service",
        "cname_pattern": "azurewebsites.net",
        "fingerprint": "404 Web Site not found",
        "takeover_possible": True,
        "severity": "HIGH"
    },
    {
        "service": "Shopify",
        "cname_pattern": "myshopify.com",
        "fingerprint": "Sorry, this shop is currently unavailable",
        "takeover_possible": True,
        "severity": "HIGH"
    },
    {
        "service": "Fastly",
        "cname_pattern": "fastly.net",
        "fingerprint": "Fastly error: unknown domain",
        "takeover_possible": True,
        "severity": "HIGH"
    },
    {
        "service": "Zendesk",
        "cname_pattern": "zendesk.com",
        "fingerprint": "Help Center Closed",
        "takeover_possible": True,
        "severity": "MEDIUM"
    },
    {
        "service": "Ghost",
        "cname_pattern": "ghost.io",
        "fingerprint": "Failed to load resource",
        "takeover_possible": True,
        "severity": "MEDIUM"
    },
]


def match_fingerprint(cname: str, body: str) -> Dict[str, Any] | None:
    """Match a CNAME and HTTP response body against the fingerprint database."""
    if not cname or not body:
        return None

    cname_lower = cname.lower()
    body_lower  = body.lower()

    for entry in FINGERPRINTS:
        if entry["cname_pattern"].lower() in cname_lower:
            if entry["fingerprint"].lower() in body_lower:
                return entry

    return None


def match_cname_only(cname: str) -> Dict[str, Any] | None:
    """Match a CNAME against known service patterns without requiring a body match."""
    if not cname:
        return None

    cname_lower = cname.lower()

    for entry in FINGERPRINTS:
        if entry["cname_pattern"].lower() in cname_lower:
            return entry

    return None
