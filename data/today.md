# depweather forecast, 2026-11-03

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-11-03T00:59:12Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 13 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 8
- New CVEs in NVD today (UTC): 1
- CVEs published in 2026-11 so far: 576 (same month last year: 3,021)

## By ecosystem

### crates.io

- **zip**: 4 advisories, worst critical; fixed in 9.0.0, 9.0.5. Example: [GHSA-m665-v7pm-7grj](https://osv.dev/vulnerability/GHSA-m665-v7pm-7grj) zip: Critical Parser Differential & Security Control Bypass via Dual-Header Inconsistencies (Zip Cloaking) Leading to Arbitrary File Overwrite & RCE

### Runtimes & servers

- **Tomcat**: 8 advisories, worst critical; fixed in 9.0.123, 10.1.61, 11.0.27. Example: [BIT-tomcat-2026-103119](https://osv.dev/vulnerability/BIT-tomcat-2026-103119) Apache Tomcat: AJP response mix-up
- **Python**: 2 advisories, worst critical; fixed in 3.11.18, 3.12.16, 3.13.18, 3.14.10 and more. Example: [BIT-libpython-2026-115557](https://osv.dev/vulnerability/BIT-libpython-2026-115557) Distrust compromised intermediate certificates in ssl module
- **Node.js (node)**: 9 advisories, worst high; fixed in 22.23.4, 24.22.1, 26.12.1. Example: [BIT-node-2026-106069](https://osv.dev/vulnerability/BIT-node-2026-106069) A flaw in Node.js TLS hostname verification can cause a server certificate to be validated against a different IP address than the one the client connected to, when the host is a non-canonical IPv4 literal with a leading zero, such as `0127.0.0.1`.

### npm

- **undici**: 6 advisories, worst high; fixed in 7.30.1, 8.12.2, 6.29.1, 8.11.2. Example: [GHSA-4w7w-5xrc-9h26](https://osv.dev/vulnerability/GHSA-4w7w-5xrc-9h26) undici vulnerable to cache poisoning and cross-user disclosure via cross-origin redirects
- **Nuxt**: 1 advisory, worst medium; fixed in 4.6.3. Example: [GHSA-9v7c-q64q-vv33](https://osv.dev/vulnerability/GHSA-9v7c-q64q-vv33) Nuxt: Dot segments in the request path bypass `server/middleware` path checks and server route rules on page routes
- **vite**: 1 advisory, worst medium; fixed in 6.4.5. Example: [GHSA-8g5g-mxqh-grgj](https://osv.dev/vulnerability/GHSA-8g5g-mxqh-grgj) Vite: `server.fs.deny` bypassed with queries

### Maven

- **guava (com.google.guava:guava)**: 1 advisory, worst high; fixed in 33.7.2. Example: [GHSA-xxph-c9ww-hj94](https://osv.dev/vulnerability/GHSA-xxph-c9ww-hj94) Google Guava: CompactHashMap/CompactHashSet/MapMakerInternalMap deserialization triggers uncontrolled memory allocation

### Packagist

- **Symfony (symfony/http-kernel)**: 2 advisories, worst high; fixed in 5.4.54, 6.4.45, 7.4.18, 8.1.6 and more. Example: [GHSA-2v3c-qxhr-7vpv](https://osv.dev/vulnerability/GHSA-2v3c-qxhr-7vpv) Symfony: Unbounded Recursion in the YAML Inline Lexer Lets a Single Document Crash the Process
- **PHPUnit (phpunit/phpunit)**: 1 advisory, worst medium; fixed in 13.4.4. Example: [GHSA-9vw2-f4vp-x7gf](https://osv.dev/vulnerability/GHSA-9vw2-f4vp-x7gf) PHPUnit vulnerable to code execution by other local users via shared temporary directory in PHPT code coverage handling

### Go

- **Echo (github.com/labstack/echo/v4)**: 10 advisories, worst high; fixed in 4.16.0, 4.15.3, 4.15.2. Example: [GHSA-375p-5qhx-8wq4](https://osv.dev/vulnerability/GHSA-375p-5qhx-8wq4) Echo's middleware.Static: `%2F`-encoded path bypasses route/group middleware guarding a statically-served path
- **Fiber (github.com/gofiber/fiber/v2)**: 1 advisory, worst medium; fixed in 2.52.3. Example: [GHSA-g5jq-qmqr-qrwf](https://osv.dev/vulnerability/GHSA-g5jq-qmqr-qrwf) Fiber: CORS wildcard origins matched without a dot boundary, allowing credentialed cross-origin reads
- **x/net (golang.org/x/net)**: 2 advisories, worst low or unrated; fixed in 0.62.0. Example: [GO-2026-6866](https://osv.dev/vulnerability/GO-2026-6866) Check all ancestor namespace transitions when rendering raw text in html in golang.org/x/net

### PyPI

No new advisories for the tracked packages.

### NuGet

No new advisories for the tracked packages.

### RubyGems

No new advisories for the tracked packages.

### Hex

No new advisories for the tracked packages.

## Added to CISA KEV this week (all vendors)

- 2026-10-30: CVE-2026-118527, Ivanti Connect Secure: Ivanti Connect Secure Generation of Predictable Numbers or Identifiers Vulnerability
- 2026-10-30: CVE-2026-111357, Ivanti Connect Secure: Ivanti Connect Secure Missing Authentication for Critical Function Vulnerability
- 2026-10-29: CVE-2026-97229, GitLab Community Edition and Enterprise Edition: GitLab Community Edition and Enterprise Edition Integer Overflow or Wraparound Vulnerability
- 2026-10-29: CVE-2026-76418, Cisco Secure Firewall ASA Software and Cisco Secure FTD Software: Cisco Secure Firewall ASA Software and Cisco Secure FTD Software Unchecked Return Value to NULL Pointer Dereference Vulnerability
- 2026-10-28: CVE-2026-41709, Broadcom VMware ESX: Broadcom VMWare ESX Insufficient Logging Vulnerability
- 2026-10-28: CVE-2026-46300, Linux Kernel: Linux Kernel Missing Initialization of a Variable Vulnerability
- 2026-10-27: CVE-2026-48356, Adobe Commerce and Magento: Adobe Commerce and Magento Unrestricted Upload of File with Dangerous Type Vulnerability
- 2026-10-27: CVE-2026-111497, Google Brotli: Google Brotli Unchecked Return Value Vulnerability

Full data: https://depweather.com/data/latest.json
