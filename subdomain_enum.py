"""
subdomain_enum.py — GhostClaim Pro by Sipar Security
Subdomain discovery via passive OSINT sources and active brute-force.

Passive sources: crt.sh, HackerTarget
Active:         Wordlist-based DNS brute-force using SecLists (industry standard).
                Searches common SecLists install locations automatically.
                If not found, prompts the user to provide a path.

Install SecLists:
    sudo apt install seclists          # Kali / Ubuntu
    brew install seclists              # macOS
    https://github.com/danielmiessler/SecLists  (manual)
"""

import os
import socket
import requests
import requests.exceptions
from typing import List, Dict

# SecLists DNS wordlists — searched in order, first match wins.
# Covers Kali Linux, Ubuntu apt install, macOS Homebrew, and manual clone locations.
SECLISTS_CANDIDATES = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
    "/usr/local/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
]

REQUEST_TIMEOUT = 10  # seconds for OSINT API calls


def _deduplicate(subdomains: List[str]) -> List[str]:
    """Return a sorted, deduplicated list of subdomains."""
    return sorted(set(sub.lower().strip() for sub in subdomains if sub))


def _passive_crtsh(domain: str) -> List[str]:
    """
    Query crt.sh certificate transparency logs for known subdomains.

    Args:
        domain: Target domain (e.g. 'example.com')

    Returns:
        List of subdomain strings found, or empty list on failure.
    """
    found: List[str] = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        entries = response.json()

        for entry in entries:
            name = entry.get("name_value", "")
            # crt.sh can return newline-separated names in one field
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    found.append(sub)

    except requests.exceptions.Timeout:
        print("[!] crt.sh request timed out. Skipping.")
    except requests.exceptions.ConnectionError:
        print("[!] Could not connect to crt.sh. Skipping.")
    except requests.exceptions.HTTPError as e:
        print(f"[!] crt.sh returned HTTP error: {e}. Skipping.")
    except ValueError:
        print("[!] crt.sh returned invalid JSON. Skipping.")

    return found


def _passive_hackertarget(domain: str) -> List[str]:
    """
    Query HackerTarget's hostsearch API for known subdomains.

    Args:
        domain: Target domain (e.g. 'example.com')

    Returns:
        List of subdomain strings found, or empty list on failure.
    """
    found: List[str] = []
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        for line in response.text.splitlines():
            if "," in line:
                sub = line.split(",")[0].strip()
                if sub.endswith(domain) and sub != domain:
                    found.append(sub)

    except requests.exceptions.Timeout:
        print("[!] HackerTarget request timed out. Skipping.")
    except requests.exceptions.ConnectionError:
        print("[!] Could not connect to HackerTarget. Skipping.")
    except requests.exceptions.HTTPError as e:
        print(f"[!] HackerTarget returned HTTP error: {e}. Skipping.")

    return found


def _find_seclists() -> str | None:
    """
    Search common SecLists install locations on this machine.

    Returns:
        Absolute path to the wordlist file if found, else None.
    """
    for path in SECLISTS_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def _get_wordlist_path(custom_wordlist: str | None) -> str | None:
    """
    Resolve which wordlist to use for brute-force.

    Priority order:
        1. --wordlist path provided by user
        2. SecLists auto-detected on this machine
        3. Prompt user to enter a path manually

    Args:
        custom_wordlist: Path provided by the user via --wordlist, or None.

    Returns:
        Absolute path to a valid wordlist file, or None if the user skips.
    """
    # 1. User provided --wordlist
    if custom_wordlist:
        if os.path.isfile(custom_wordlist):
            return custom_wordlist
        print(f"[!] Wordlist not found at: {custom_wordlist}")

    # 2. Auto-detect SecLists
    seclists_path = _find_seclists()
    if seclists_path:
        print(f"[*] SecLists detected: {seclists_path}")
        return seclists_path

    # 3. SecLists not installed — prompt user
    print("[!] SecLists not found on this system.")
    print("[i] Install it with:  sudo apt install seclists  (Kali/Ubuntu)")
    print("[i]                   brew install seclists      (macOS)")
    print("[i] Or provide any wordlist file path below.")
    print()

    user_input = input("[?] Enter wordlist path (or press Enter to skip brute-force): ").strip()

    if not user_input:
        print("[!] No wordlist provided. Skipping active brute-force.")
        return None

    if os.path.isfile(user_input):
        return user_input

    print(f"[!] File not found: {user_input}. Skipping active brute-force.")
    return None


def _active_bruteforce(domain: str, wordlist_path: str) -> List[str]:
    """
    DNS brute-force: attempt to resolve each word.<domain> from a wordlist.

    Only keeps subdomains that return a valid DNS answer.

    Args:
        domain:        Target domain
        wordlist_path: Path to wordlist file

    Returns:
        List of live subdomain strings.
    """
    found: List[str] = []

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except OSError as e:
        print(f"[!] Could not read wordlist: {e}")
        return found

    for word in words:
        candidate = f"{word}.{domain}"
        try:
            socket.getaddrinfo(candidate, None)
            found.append(candidate)
        except socket.gaierror:
            pass  # Does not resolve — not live

    return found


def enumerate_subdomains(
    domain: str,
    wordlist: str | None = None,
    skip_enum: bool = False,
) -> List[Dict[str, str]]:
    """
    Discover subdomains for a target domain using passive and active methods.

    Args:
        domain:     Target domain (e.g. 'example.com')
        wordlist:   Optional custom wordlist path for brute-force
        skip_enum:  If True, return only the root domain (no enumeration)

    Returns:
        List of dicts: [{"subdomain": "sub.example.com"}, ...]
    """
    if skip_enum:
        return [{"subdomain": domain}]

    all_found: List[str] = []

    # ── Passive sources ───────────────────────────────────────────────────────
    print("[*] Querying crt.sh...")
    all_found.extend(_passive_crtsh(domain))

    print("[*] Querying HackerTarget...")
    all_found.extend(_passive_hackertarget(domain))

    # ── Active brute-force ────────────────────────────────────────────────────
    wordlist_path = _get_wordlist_path(wordlist)
    if wordlist_path:
        print(f"[*] Brute-forcing with wordlist: {wordlist_path}")
        all_found.extend(_active_bruteforce(domain, wordlist_path))
    else:
        print("[!] No wordlist available. Skipping active brute-force.")

    # ── Deduplicate and return ────────────────────────────────────────────────
    unique = _deduplicate(all_found)
    return [{"subdomain": sub} for sub in unique]
