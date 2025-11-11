# BizLogic Scanner - Advanced Business Logic Vulnerability Framework
## ✩₊˚.⋆☾⋆⁺₊✧by:ek0ms savi0r✩₊˚.⋆☾⋆⁺₊✧
## Overview

BizLogic Scanner is an interactive, modular business-logic heuristic scanner with advanced exploitation capabilities. Built for red teams and ethical hackers, this framework systematically identifies business logic flaws that traditional vulnerability scanners miss. The tool employs conservative crawling, intelligent detection heuristics, and optional exploitation modules to validate findings in a controlled manner.

## Core Capabilities

- **Heuristic Business Logic Detection**: Identifies logic flaws in authentication, authorization, workflow enforcement, and resource management
- **Conservative Crawling**: Same-origin crawling with configurable rate limiting to avoid target impact
- **Advanced Discovery**: Automated discovery of robots.txt, sitemaps, and OpenAPI specifications
- **Form Analysis**: Comprehensive form parsing and analysis for client-side enforcement bypass
- **Optional Authentication Support**: Second-pass authenticated scanning with supplied headers
- **Controlled Exploitation**: Safe exploitation modules with built-in safety limits
- **Multi-Format Reporting**: Text, JSON, HTML, and Nuclei-compatible template exports

---

## Installation

Clone the repository and prepare your environment:

```bash
git clone https://github.com/ekomsSavior/bizlogic
cd bizlogic
```

This tool requires Python 3.6+ with the following dependencies. Install them manually:

```bash
pip install requests beautifulsoup4
```

## Usage

### Basic Operation

Execute the scanner:

```bash
python bizlogic_scanner.py
```

The tool will prompt you for:
- Target base URL (e.g., https://example.com)
- Request rate limit (default: 0.5 seconds between requests)
- Maximum pages to crawl (default: 50)

### Scan Phases

1. **Discovery Phase**: The scanner performs conservative same-origin crawling, discovers robots.txt, sitemaps, and OpenAPI endpoints
2. **Authentication Detection**: Identifies login forms and optionally prompts for authentication headers for deeper scanning
3. **Heuristic Analysis**: Runs nine specialized checks for business logic vulnerabilities
4. **Exploitation Phase**: Optional controlled exploitation of identified vulnerabilities

### Exploitation Module

If you choose to enable exploitation, the scanner will attempt controlled validation of identified vulnerabilities:

- **IDOR Exploitation**: Tests predictable ID sequences with safety limits
- **Token Bypass**: Attempts token parameter manipulation and removal
- **Password Recovery Testing**: Tests recovery mechanisms for user enumeration and weak verification
- **API Endpoint Probing**: Tests discovered API endpoints with various HTTP methods
- **Client-Side Bypass**: Attempts to bypass client-side validation through direct form submission

**Exploitation Safety Controls:**
- Maximum 5 attempts per finding
- Slower request rate (1.0 seconds between exploitation requests)
- Non-destructive payloads only
- Automatic termination after safety limits

### Output and Reporting

The scanner generates comprehensive reports in multiple formats:

- **Text Report**: Detailed findings with evidence and remediation guidance
- **JSON Export**: Machine-readable format for integration with other tools
- **HTML Report**: Formatted web view of results
- **Nuclei Templates**: Export detected patterns as Nuclei-compatible templates

Reports are saved to timestamped directories under `reports/scan_[domain]_[timestamp]/`

## Key Detection Categories

- Unverified ownership claims and transfers
- Authentication bypass via alternate channels
- Authorization bypass through user-controlled keys
- Weak password recovery mechanisms
- Incorrect ownership assignment
- Resource allocation without limits
- Premature resource release
- Single unique action enforcement flaws
- Client-side workflow enforcement

## Operational Security Notes

- The scanner uses conservative User-Agent headers and rate limiting by default
- All requests originate from the same session to maintain state
- Exploitation modules include automatic safety limits
- No persistent connections or background processes

---

## Legal and Ethical Disclaimer

**WARNING: This tool is designed for authorized security testing only.**

You must have explicit written permission to test any system before using this tool. Unauthorized testing is illegal and unethical. 

✩₊˚.⋆☾⋆⁺₊✧ek0ms savi0r✩₊˚.⋆☾⋆⁺₊✧ assumes no liability for misuse of this software.

Business logic vulnerabilities can cause serious business impact if exploited maliciously. 

Use this tool responsibly and always in accordance with your testing scope and rules of engagement.

