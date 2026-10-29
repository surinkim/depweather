# depweather forecast, 2026-10-29

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-10-29T22:45:31Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 16 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 10
- New CVEs in NVD today (UTC): 533
- CVEs published in 2026-10 so far: 16,275 (same month last year: 4,273)

## By ecosystem

### Runtimes & servers

- **Node.js (node)**: 10 advisories, worst actively exploited (CISA KEV); fixed in 22.23.4, 24.22.1, 26.12.1. Example: [BIT-node-2026-111497](https://osv.dev/vulnerability/BIT-node-2026-111497) A flaw in Node.js can cause Node.js Brotli decoder out-of-bounds write permits remote code execution. This vulnerability affects Node.js 22.x, 24.x, and 26.x.
- **PHP**: 2 advisories, worst actively exploited (CISA KEV); fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12. Example: [BIT-libphp-2026-109619](https://osv.dev/vulnerability/BIT-libphp-2026-109619) RCE via stale global state
- **Tomcat**: 8 advisories, worst critical; fixed in 9.0.123, 10.1.61, 11.0.27. Example: [BIT-tomcat-2026-103119](https://osv.dev/vulnerability/BIT-tomcat-2026-103119) Apache Tomcat: AJP response mix-up
- **Python**: 1 advisory, worst medium; fixed in 3.11.18, 3.12.16, 3.13.18, 3.14.10 and more. Example: [BIT-libpython-2026-114583](https://osv.dev/vulnerability/BIT-libpython-2026-114583) tar filter allows writing outside destination via empty-named symlink

### crates.io

- **zip**: 5 advisories, worst critical; fixed in 9.0.0, 9.0.5. Example: [GHSA-m665-v7pm-7grj](https://osv.dev/vulnerability/GHSA-m665-v7pm-7grj) zip: Critical Parser Differential & Security Control Bypass via Dual-Header Inconsistencies (Zip Cloaking) Leading to Arbitrary File Overwrite & RCE

### Packagist

- **Laravel (laravel/framework)**: 2 advisories, worst critical; fixed in 13.29.0, 12.68.0, 13.27.0. Example: [GHSA-f9x3-7vq9-cph6](https://osv.dev/vulnerability/GHSA-f9x3-7vq9-cph6) Laravel TokenGuard authentication bypass through non-string API credentials
- **Symfony (symfony/http-kernel)**: 2 advisories, worst high; fixed in 5.4.54, 6.4.45, 7.4.18, 8.1.6 and more. Example: [GHSA-2v3c-qxhr-7vpv](https://osv.dev/vulnerability/GHSA-2v3c-qxhr-7vpv) Symfony: Unbounded Recursion in the YAML Inline Lexer Lets a Single Document Crash the Process

### Go

- **Echo (github.com/labstack/echo/v4)**: 14 advisories, worst critical; fixed in 4.16.0, 4.15.3, 4.15.2, 4.16.1. Example: [GHSA-cxf3-9h37-7rr8](https://osv.dev/vulnerability/GHSA-cxf3-9h37-7rr8) Echo: Rejected WebSocket upgrades can bypass Echo route-level access controls
- **x/net (golang.org/x/net)**: 2 advisories, worst low or unrated; fixed in 0.62.0. Example: [GO-2026-6866](https://osv.dev/vulnerability/GO-2026-6866) Check all ancestor namespace transitions when rendering raw text in html in golang.org/x/net

### Hex

- **hackney**: 5 advisories, worst critical; fixed in 4.9.0. Example: [EEF-CVE-2026-115693](https://osv.dev/vulnerability/EEF-CVE-2026-115693) Custom cacerts or cacertfile do not restrict trust to the pinned CA in hackney
- **plug**: 1 advisory, worst medium; fixed in 1.7.0. Example: [EEF-CVE-2026-105963](https://osv.dev/vulnerability/EEF-CVE-2026-105963) Secret key base exposed in stack trace arguments on wrong-typed Plug.Crypto arguments

### npm

- **undici**: 9 advisories, worst high; fixed in 7.30.1, 8.12.2, 6.29.1, 8.11.2. Example: [GHSA-4w7w-5xrc-9h26](https://osv.dev/vulnerability/GHSA-4w7w-5xrc-9h26) undici vulnerable to cache poisoning and cross-user disclosure via cross-origin redirects
- **SvelteKit (@sveltejs/kit)**: 2 advisories, worst medium; fixed in 3.0.0. Example: [GHSA-pfhg-q3qv-9q6r](https://osv.dev/vulnerability/GHSA-pfhg-q3qv-9q6r) SvelteKit: URL redirection to untrusted site via enhanced form submission
- **vite**: 1 advisory, worst medium; fixed in 6.4.5. Example: [GHSA-8g5g-mxqh-grgj](https://osv.dev/vulnerability/GHSA-8g5g-mxqh-grgj) Vite: `server.fs.deny` bypassed with queries

### Maven

- **guava (com.google.guava:guava)**: 1 advisory, worst high; fixed in 33.7.2. Example: [GHSA-xxph-c9ww-hj94](https://osv.dev/vulnerability/GHSA-xxph-c9ww-hj94) Google Guava: CompactHashMap/CompactHashSet/MapMakerInternalMap deserialization triggers uncontrolled memory allocation

### PyPI

- **setuptools**: 1 advisory, worst low or unrated; fixed in 84.1.0. Example: [GHSA-xmj3-9gf7-h52w](https://osv.dev/vulnerability/GHSA-xmj3-9gf7-h52w) setuptools: Windows path escape via namespace_packages.txt during legacy wheel installation  Description

### NuGet

No new advisories for the tracked packages.

### RubyGems

No new advisories for the tracked packages.

## Added to CISA KEV this week (all vendors)

- 2026-10-29: CVE-2026-97229, GitLab Community Edition and Enterprise Edition: GitLab Community Edition and Enterprise Edition Integer Overflow or Wraparound Vulnerability
- 2026-10-29: CVE-2026-76418, Cisco Secure Firewall ASA Software and Cisco Secure FTD Software: Cisco Secure Firewall ASA Software and Cisco Secure FTD Software Unchecked Return Value to NULL Pointer Dereference Vulnerability
- 2026-10-28: CVE-2026-41709, Broadcom VMware ESX: Broadcom VMWare ESX Insufficient Logging Vulnerability
- 2026-10-28: CVE-2026-46300, Linux Kernel: Linux Kernel Missing Initialization of a Variable Vulnerability
- 2026-10-27: CVE-2026-48356, Adobe Commerce and Magento: Adobe Commerce and Magento Unrestricted Upload of File with Dangerous Type Vulnerability
- 2026-10-27: CVE-2026-111497, Google Brotli: Google Brotli Unchecked Return Value Vulnerability
- 2026-10-26: CVE-2026-109618, PHP Group PHP: PHP Memory Corruption Vulnerability
- 2026-10-26: CVE-2026-109619, PHP Group PHP: PHP Stale Internal Request-State Vulnerability
- 2026-10-23: CVE-2026-114625, Arista VeloCloud Orchestrator: Arista VeloCloud Orchestrator SQL Injection Vulnerability
- 2026-10-23: CVE-2026-110447, Collabora Collabora Online – Built-in CODE Server: Collabora Online – Built-in CODE Server OS Command Injection Vulnerability

Full data: https://depweather.com/data/latest.json
