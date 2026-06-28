"""
dns_resolver.py — GhostClaim Pro by Sipar Security
DNS resolution and full CNAME chain following using dnspython.
"""

import dns.resolver
import dns.exception
from typing import Dict, List, Any

# Maximum hops to follow in a CNAME chain (prevents infinite loops)
MAX_CNAME_DEPTH = 10


def resolve_subdomain(subdomain: str) -> Dict[str, Any]:
    """
    Resolve a subdomain and follow its full CNAME chain.

    Follows CNAME records recursively until reaching an A record or NXDOMAIN.
    Returns structured DNS data for use by the takeover engine.

    Args:
        subdomain: The subdomain to resolve (e.g. 'blog.example.com')

    Returns:
        Dict containing:
            - subdomain:    The input subdomain
            - cname_chain:  Full list of CNAME hops including the start
            - final_cname:  Last CNAME target before an A record or NXDOMAIN
            - a_records:    List of resolved IP addresses (may be empty)
            - resolved:     True if any DNS answer was obtained
            - nxdomain:     True if final target returned NXDOMAIN (dangling CNAME)
            - error:        Error message string if resolution failed, else None
    """
    result: Dict[str, Any] = {
        "subdomain": subdomain,
        "cname_chain": [],
        "final_cname": None,
        "a_records": [],
        "resolved": False,
        "nxdomain": False,
        "error": None,
    }

    cname_chain: List[str] = [subdomain]
    current = subdomain

    # ── Follow CNAME chain ────────────────────────────────────────────────────
    for _ in range(MAX_CNAME_DEPTH):
        try:
            cname_answer = dns.resolver.resolve(current, "CNAME")
            next_target = str(cname_answer[0].target).rstrip(".")
            cname_chain.append(next_target)
            current = next_target

        except dns.resolver.NXDOMAIN:
            # The current target does not exist — dangling CNAME
            result["nxdomain"] = True
            result["resolved"] = True
            break

        except dns.resolver.NoAnswer:
            # No CNAME record at this hop — try resolving A records below
            break

        except dns.exception.Timeout:
            result["error"] = f"DNS timeout while resolving CNAME for {current}"
            result["cname_chain"] = cname_chain
            return result

        except dns.resolver.NoNameservers:
            result["error"] = f"No nameservers available for {current}"
            result["cname_chain"] = cname_chain
            return result

    result["cname_chain"] = cname_chain
    result["final_cname"] = cname_chain[-1] if len(cname_chain) > 1 else None

    # ── Resolve A records at the end of the chain ─────────────────────────────
    if not result["nxdomain"]:
        try:
            a_answer = dns.resolver.resolve(current, "A")
            result["a_records"] = [str(rdata) for rdata in a_answer]
            result["resolved"] = True

        except dns.resolver.NXDOMAIN:
            result["nxdomain"] = True
            result["resolved"] = True

        except dns.resolver.NoAnswer:
            # Host exists but no A record (e.g. AAAA only, or MX only)
            result["resolved"] = True

        except dns.exception.Timeout:
            result["error"] = f"DNS timeout while resolving A record for {current}"

        except dns.resolver.NoNameservers:
            result["error"] = f"No nameservers available for {current}"

    return result


def is_dangling(dns_result: Dict[str, Any]) -> bool:
    """
    Return True if the DNS result indicates a dangling CNAME
    (points to a non-existent host — a prerequisite for subdomain takeover).

    Args:
        dns_result: Output from resolve_subdomain()

    Returns:
        True if CNAME chain ends in NXDOMAIN, False otherwise.
    """
    return bool(
        dns_result.get("final_cname")
        and dns_result.get("nxdomain")
    )
