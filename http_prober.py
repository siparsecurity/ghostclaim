"""
http_prober.py — GhostClaim Pro by Sipar Security
HTTP/HTTPS response fetching for subdomain takeover fingerprinting.
"""

import requests
import urllib3
from typing import Dict, Any

# Suppress SSL warnings — targets may have broken or self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; GhostClaim/1.0)"
}

BODY_SNIPPET_MAX = 500


def probe(subdomain: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Fetch the HTTP/HTTPS response for a subdomain.

    Tries HTTPS first, falls back to HTTP if HTTPS fails.
    Returns a body snippet and status code for fingerprint matching.

    Args:
        subdomain: The subdomain to probe (e.g. 'blog.example.com')
        timeout:   Request timeout in seconds (default: 5)

    Returns:
        Dict containing:
            - subdomain:     The input subdomain
            - status_code:   HTTP status code, or None on error
            - body_snippet:  First 500 characters of the response body
            - final_url:     The URL that was ultimately fetched (after redirects)
            - error:         Error message string if request failed, else None
    """
    result: Dict[str, Any] = {
        "subdomain": subdomain,
        "status_code": None,
        "body_snippet": "",
        "final_url": None,
        "error": None,
    }

    urls_to_try = [
        f"https://{subdomain}",
        f"http://{subdomain}",
    ]

    for url in urls_to_try:
        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            result["status_code"] = response.status_code
            result["body_snippet"] = response.text[:BODY_SNIPPET_MAX]
            result["final_url"] = response.url
            result["error"] = None
            return result

        except requests.exceptions.SSLError:
            # SSL failed on HTTPS — try HTTP next
            continue

        except requests.exceptions.Timeout:
            result["error"] = f"Request timed out for {url}"
            continue

        except requests.exceptions.ConnectionError:
            result["error"] = f"Connection error for {url}"
            continue

    # Both HTTPS and HTTP failed — return the last error
    return result


def probe_batch(subdomains: list, timeout: int = 5) -> list:
    """
    Probe a list of subdomains sequentially.

    Args:
        subdomains: List of subdomain strings
        timeout:    Per-request timeout in seconds

    Returns:
        List of probe result dicts (one per subdomain).
    """
    return [probe(sub, timeout=timeout) for sub in subdomains]
