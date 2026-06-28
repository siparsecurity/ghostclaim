"""
main.py — GhostClaim Free by Sipar Security
CLI entry point for subdomain takeover detection.
"""

import argparse
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table
from rich.text import Text

import dns_resolver
import http_prober
import subdomain_enum
import takeover_engine

console = Console()

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+[a-zA-Z]{2,}$"
)

BANNER = r"""
  _____ _               _    _____ _       _
 / ____| |             | |  / ____| |     (_)
| |  __| |__   ___  ___| |_| |    | | __ _ _ _ __ ___
| | |_ | '_ \ / _ \/ __| __| |    | |/ _` | | '_ ` _ \\
| |__| | | | | (_) \__ \ |_| |____| | (_| | | | | | | |
 \_____|_| |_|\___/|___/\__|\_____\|_|\__,_|_|_| |_| |_|
                                                F R E E
"""


def print_banner() -> None:
    """Print the GhostClaim Free ASCII banner."""
    console.print(f"[bold green]{BANNER}[/bold green]")
    console.print(
        "[bold white]GhostClaim Free v1.0[/bold white] — "
        "[dim]Subdomain Takeover Detection[/dim]\n"
        "[dim]by Sipar Security · siparsecurity.github.io[/dim]\n"
    )


def validate_domain(domain: str) -> bool:
    """Validate a domain name against a strict regex pattern."""
    return bool(DOMAIN_REGEX.match(domain))


def build_args() -> argparse.Namespace:
    """Parse and return CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="ghostclaim",
        description="GhostClaim Free — Subdomain Takeover Detection by Sipar Security",
        epilog="""
Upgrade to GhostClaim Pro for:
  - 30+ service fingerprints (vs 10 in free)
  - Stealth modes for WAF evasion
  - JSON export
  - HTML and PDF report generation

  --> siparsecurity.github.io
        """
    )
    parser.add_argument(
        "--domain", required=True,
        help="Target domain to scan (e.g. example.com)"
    )
    parser.add_argument(
        "--skip-enum", action="store_true",
        help="Skip subdomain enumeration; check root domain only"
    )
    parser.add_argument(
        "--wordlist",
        help="Custom wordlist path for active brute-force"
    )
    parser.add_argument(
        "--threads", type=int, default=10,
        help="Number of threads for DNS resolution and HTTP probing (default: 10)"
    )
    parser.add_argument(
        "--timeout", type=int, default=5,
        help="HTTP request timeout in seconds (default: 5)"
    )
    return parser.parse_args()


def confirm_authorization(domain: str) -> bool:
    """Prompt the user to confirm they are authorized to test the target."""
    console.print(
        f"\n[bold yellow][!] Authorization check[/bold yellow]\n"
        f"    You are about to scan: [bold]{domain}[/bold]\n"
        f"    Only test domains you own or have explicit written permission to test.\n"
        f"    Unauthorized scanning may be illegal in your jurisdiction.\n"
    )
    answer = input("    Do you have authorization to test this domain? [y/N]: ").strip().lower()
    return answer == "y"


def resolve_worker(subdomain_str: str) -> Dict[str, Any]:
    """Thread worker: resolve DNS for a single subdomain."""
    return dns_resolver.resolve_subdomain(subdomain_str)


def probe_worker(args: tuple) -> Dict[str, Any]:
    """Thread worker: HTTP probe for a single subdomain."""
    subdomain_str, timeout = args
    return http_prober.probe(subdomain_str, timeout=timeout)


def print_results_table(findings: List[Dict[str, Any]]) -> None:
    """Render the findings table to the terminal using rich."""
    table = Table(
        show_header=True,
        header_style="bold green",
        border_style="dim",
        expand=True,
    )
    table.add_column("Subdomain", style="white", no_wrap=False)
    table.add_column("Service", style="cyan")
    table.add_column("Verdict", justify="center")
    table.add_column("Confidence", justify="center")
    table.add_column("Severity", justify="center")

    VERDICT_COLORS = {
        "VULNERABLE":             "bold red",
        "POTENTIALLY_VULNERABLE": "bold yellow",
        "SAFE":                   "bold green",
        "ERROR":                  "dim",
    }
    SEV_COLORS = {
        "HIGH":   "red",
        "MEDIUM": "yellow",
        "LOW":    "cyan",
        "NONE":   "dim",
    }

    for f in findings:
        verdict   = f.get("verdict", "ERROR")
        confidence = f.get("confidence", "—")
        service   = f.get("service") or "—"
        severity  = f.get("severity", "NONE")

        verdict_label = verdict.replace("_VULNERABLE", " VULN")
        verdict_text  = Text(verdict_label, style=VERDICT_COLORS.get(verdict, "white"))
        sev_text      = Text(severity, style=SEV_COLORS.get(severity, "white"))

        table.add_row(
            f.get("subdomain", ""),
            service,
            verdict_text,
            confidence,
            sev_text,
        )

    console.print(table)


def main() -> None:
    """Main entry point: orchestrate the full GhostClaim Free scan."""

    print_banner()
    args = build_args()

    # ── Domain validation ─────────────────────────────────────────────────────
    if not validate_domain(args.domain):
        console.print(f"[bold red][!] Invalid domain format: {args.domain}[/bold red]")
        sys.exit(1)

    # ── Authorization prompt ──────────────────────────────────────────────────
    if not confirm_authorization(args.domain):
        console.print("[bold red][!] Scan aborted. Authorization not confirmed.[/bold red]")
        sys.exit(0)

    # ── Step 1: Subdomain enumeration ─────────────────────────────────────────
    console.print(f"\n[bold][*][/bold] Target: [bold green]{args.domain}[/bold green]")
    console.print("[*] Enumerating subdomains...")

    subdomains = subdomain_enum.enumerate_subdomains(
        domain=args.domain,
        wordlist=args.wordlist,
        skip_enum=args.skip_enum,
    )
    console.print(f"[bold green][+][/bold green] Found {len(subdomains)} subdomains")

    subdomain_strings = [s["subdomain"] for s in subdomains]

    # ── Step 2: DNS resolution (threaded) ────────────────────────────────────
    console.print("[*] Resolving DNS records...")
    dns_results: Dict[str, Dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {
            executor.submit(resolve_worker, sub): sub
            for sub in subdomain_strings
        }
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                dns_results[sub] = future.result()
            except socket.gaierror as e:
                dns_results[sub] = {
                    "subdomain": sub,
                    "cname_chain": [],
                    "final_cname": None,
                    "a_records": [],
                    "resolved": False,
                    "nxdomain": False,
                    "error": str(e),
                }

    cname_subs = [
        sub for sub in subdomain_strings
        if dns_results.get(sub, {}).get("final_cname")
    ]
    console.print(f"[*] Found {len(cname_subs)} subdomains with CNAME records to probe")

    # ── Step 3: HTTP probing (threaded) ───────────────────────────────────────
    console.print("[*] Probing HTTP responses...")
    http_results: Dict[str, Dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {
            executor.submit(probe_worker, (sub, args.timeout)): sub
            for sub in cname_subs
        }
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                http_results[sub] = future.result()
            except Exception:
                http_results[sub] = {
                    "subdomain": sub,
                    "status_code": None,
                    "body_snippet": "",
                    "final_url": None,
                    "error": "Unexpected error during HTTP probe",
                }

    # ── Step 4: Takeover analysis ─────────────────────────────────────────────
    findings: List[Dict[str, Any]] = []

    for sub in subdomain_strings:
        dns_res  = dns_results.get(sub, {
            "subdomain": sub, "cname_chain": [], "final_cname": None,
            "a_records": [], "resolved": False, "nxdomain": False,
            "error": "DNS result missing"
        })
        http_res = http_results.get(sub, {
            "subdomain": sub, "status_code": None,
            "body_snippet": "", "final_url": None,
            "error": "Not probed (no CNAME)"
        })
        finding = takeover_engine.analyze(dns_res, http_res)
        findings.append(finding)

    summary = takeover_engine.summarize(findings)

    # ── Step 5: Print results table ───────────────────────────────────────────
    console.print("\n")
    print_results_table(findings)

    # ── Step 6: Summary output ────────────────────────────────────────────────
    console.print()
    if summary["vulnerable"] > 0:
        console.print(
            f"[bold red][!!!] {summary['vulnerable']} VULNERABLE subdomain(s) found.[/bold red]"
        )
    if summary["potentially_vulnerable"] > 0:
        console.print(
            f"[bold yellow][!] {summary['potentially_vulnerable']} POTENTIALLY VULNERABLE "
            f"subdomain(s) require manual verification.[/bold yellow]"
        )
    if summary["vulnerable"] == 0 and summary["potentially_vulnerable"] == 0:
        console.print("[bold green][+] No vulnerable subdomains detected.[/bold green]")

    console.print()
    console.print("[dim][i] Always verify findings manually before reporting.[/dim]")
    console.print("[dim][i] For authorized testing only. Sipar Security.[/dim]")
    console.print()
    console.print("[dim][i] Upgrade to GhostClaim Pro for stealth modes, JSON export, and PDF reports.[/dim]")
    console.print("[dim][i] --> siparsecurity.github.io[/dim]\n")


if __name__ == "__main__":
    main()
