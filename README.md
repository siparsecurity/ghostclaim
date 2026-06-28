# GhostClaim — Subdomain Takeover Detection Tool

**By Sipar Security** | [siparsecurity.github.io](https://siparsecurity.github.io)

GhostClaim is an open-source subdomain takeover detection tool built for penetration testers and bug bounty hunters. It enumerates subdomains, follows CNAME chains, and fingerprints HTTP responses against a database of known vulnerable services.

---

## Features

- Passive subdomain enumeration via crt.sh and HackerTarget
- Active brute-force using built-in wordlist or SecLists
- Full CNAME chain following
- Fingerprint matching against 10 known vulnerable services
- Clean terminal output with verdict table
- Verdicts: VULNERABLE / POTENTIALLY VULNERABLE / SAFE / ERROR

---

## Installation

```bash
git clone https://github.com/siparsecurity/ghostclaim.git
cd ghostclaim
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> **Windows users:** use `venv\Scripts\activate` instead of `source venv/bin/activate`

> Modern Kali Linux systems block `pip install` outside a virtual environment. The venv step is required.

---

## Usage

```bash
python3 main.py --domain example.com
python3 main.py --domain example.com --wordlist /path/to/wordlist.txt
python3 main.py --domain example.com --skip-enum
python3 main.py --domain example.com --threads 20
```

Run `python3 main.py --help` for all available options.

---

## Free vs Pro

| Feature | Free | Pro |
|---|---|---|
| Passive subdomain enumeration | ✅ | ✅ |
| Active brute-force | ✅ | ✅ |
| CNAME chain following | ✅ | ✅ |
| Fingerprint database | 10 services | 30+ services |
| Stealth modes | ❌ | ✅ |
| JSON export | ❌ | ✅ |
| HTML report generation | ❌ | ✅ |
| PDF report generation | ❌ | ✅ |

---

## Get Pro

GhostClaim Pro includes 30+ service fingerprints, stealth modes, JSON export, and HTML/PDF report generation. Sold directly — no payment platform required.

**WhatsApp:** +923189352428
**Email:** siparsecurity@gmail.com
**LinkedIn:** [linkedin.com/company/siparsecurity](https://linkedin.com/company/siparsecurity)

---

## Responsible Use

This tool is for authorized security testing only. Always have written permission before scanning any target.

---

## About

Sipar Security is an offensive security company based in Pakistan building open-source tools for penetration testers and bug bounty hunters.

- Website: [siparsecurity.github.io](https://siparsecurity.github.io)
- Email: siparsecurity@gmail.com

---

*For authorized testing only. Sipar Security.*
