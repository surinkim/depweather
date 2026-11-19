# depweather forecast, 2026-11-19

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-11-19T00:23:36Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 19 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 7
- New CVEs in NVD today (UTC): 42
- CVEs published in 2026-11 so far: 10,315 (same month last year: 3,021)

## By ecosystem

### Runtimes & servers

- **Ruby**: 1 advisory, worst actively exploited (CISA KEV); fixed in 3.3.13, 3.4.12, 4.0.8. Example: [BIT-ruby-2026-97229](https://osv.dev/vulnerability/BIT-ruby-2026-97229) Integer Overflow or Wraparound in GitLab
- **WordPress**: 1 advisory, worst actively exploited (CISA KEV); fixed in 4.7.39, 4.8.34, 4.9.35, 5.0.31 and more. Example: [BIT-wordpress-2026-119977](https://osv.dev/vulnerability/BIT-wordpress-2026-119977) WordPress Core 4.7.0 - 7.1.3 - Unauthenticated Upgrade-Window Staged-Installer Remote Code Execution
- **MongoDB**: 1 advisory, worst critical; fixed in 4.4.32, 5.0.35, 6.0.30, 7.0.48 and more. Example: [BIT-mongodb-2026-118383](https://osv.dev/vulnerability/BIT-mongodb-2026-118383) Pre-authentication use-after-free in MongoDB Server replica set primary catch-up
- **PostgreSQL**: 52 advisories, worst high. Example: [DEBIAN-CVE-2026-18447](https://osv.dev/vulnerability/DEBIAN-CVE-2026-18447) Type confusion in PostgreSQL SQL-language functions allows an object creator to execute arbitrary code as the operating system user running the database, via an output parameter of type "any".  Versions before PostgreSQL 18.7, 17.12, 16.16, 15.20, and 14.25 are affected.
- **Java (OpenJDK) (java)**: 10 advisories, worst high. Example: [DEBIAN-CVE-2026-114940](https://osv.dev/vulnerability/DEBIAN-CVE-2026-114940) Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511b33, 8u511b33-perf, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM
- **Python**: 3 advisories, worst high; fixed in 3.14.11, 3.16.0. Example: [BIT-libpython-2026-119170](https://osv.dev/vulnerability/BIT-libpython-2026-119170) Regression in FIPS enforcement of hash algorithms affecting only Python 3.14.10
- **Apache httpd (apache)**: 1 advisory, worst high; fixed in 2.4.71. Example: [BIT-apache-2026-119618](https://osv.dev/vulnerability/BIT-apache-2026-119618) Apache HTTP Server: mod_http2: heap corruption and RCE in assign_headers
- **MariaDB**: 1 advisory, worst high; fixed in 10.11.19, 11.4.13, 11.8.9, 12.3.3 and more. Example: [BIT-mariadb-2026-102523](https://osv.dev/vulnerability/BIT-mariadb-2026-102523) MariaDB server: Authorization bypass via ALTER TABLE ... CONVERT ... PARTITION

### RubyGems

- **Ruby on Rails (rails)**: 10 advisories, worst critical; fixed in 8.1.4.1, 8.0.5.2. Example: [GHSA-f3w6-w445-fwh9](https://osv.dev/vulnerability/GHSA-f3w6-w445-fwh9) Active Storage: Possible arbitrary file write and read in image analysis

### npm

- **SvelteKit (@sveltejs/kit)**: 5 advisories, worst high; fixed in 3.1.1, 2.70.4. Example: [GHSA-m9j8-jcmv-hp69](https://osv.dev/vulnerability/GHSA-m9j8-jcmv-hp69) SvelteKit: Build-time server-only module import guard could fail, resulting in server secrets being statically replaced in client bundle
- **Hono**: 5 advisories, worst medium; fixed in 4.13.16. Example: [GHSA-46wx-v44x-9hh2](https://osv.dev/vulnerability/GHSA-46wx-v44x-9hh2) Hono: `csrf()` does not check requests sent by hyperlink auditing (`text/ping`)
- **Nuxt**: 4 advisories, worst medium; fixed in 4.6.4. Example: [GHSA-96x6-fvhx-49hg](https://osv.dev/vulnerability/GHSA-96x6-fvhx-49hg) Nuxt exposes the message and data of unhandled errors thrown during server rendering
- **Next.js (next)**: 2 advisories, worst medium; fixed in 16.4.5. Example: [GHSA-vc7v-qv4w-wrv8](https://osv.dev/vulnerability/GHSA-vc7v-qv4w-wrv8) Next.js: Cache leak across root param values in nested 'use cache' functions via delayed inner stream metadata
- **Astro**: 2 advisories, worst medium; fixed in 7.4.5, 7.4.7. Example: [GHSA-r3h5-4585-7x3w](https://osv.dev/vulnerability/GHSA-r3h5-4585-7x3w) Astro: Image endpoint in @astrojs/node can read files from a case-variant sibling of the output directory on case-sensitive filesystems

### PyPI

- **aiohttp**: 9 advisories, worst high; fixed in 3.14.4. Example: [GHSA-jm3w-gw2p-xjfj](https://osv.dev/vulnerability/GHSA-jm3w-gw2p-xjfj) AIOHTTP: Event loop stall in add_domain() wildcard matching
- **pillow**: 2 advisories, worst high; fixed in 13.0.0. Example: [GHSA-xcvg-w56q-r89m](https://osv.dev/vulnerability/GHSA-xcvg-w56q-r89m) Pillow: Heap buffer overflow saving TIFF with libtiff when tags override image size

### Hex

- **plug**: 1 advisory, worst medium; fixed in 1.20.4. Example: [EEF-CVE-2026-120287](https://osv.dev/vulnerability/EEF-CVE-2026-120287) Multipart `:length` limit not charged for part and header framing in Plug.Parsers.MULTIPART

### Packagist

- **Drupal core (drupal/core)**: 2 advisories, worst low or unrated; fixed in 10.6.22, 11.3.22, 11.4.13. Example: [DRUPAL-CORE-2026-017](https://osv.dev/vulnerability/DRUPAL-CORE-2026-017) Drupal core ships with an `install.php` file for installing Drupal core.
- **Laravel (laravel/framework)**: 1 advisory, worst low or unrated; fixed in 12.71.0, 13.40.0. Example: [GHSA-63hm-g96r-2m2q](https://osv.dev/vulnerability/GHSA-63hm-g96r-2m2q) Laravel: Task Output Injection - Concurrency Process

### Maven

No new advisories for the tracked packages.

### NuGet

No new advisories for the tracked packages.

### crates.io

No new advisories for the tracked packages.

### Go

No new advisories for the tracked packages.

## Added to CISA KEV this week (all vendors)

- 2026-11-18: CVE-2024-10441, Synology DiskStation Manager (DSM): Synology DiskStation Manager (DSM) Improper Encoding or Escaping of Output Vulnerability
- 2026-11-18: CVE-2026-40217, BerriAI LiteLLM: BerriAI LiteLLM Unprotected Alternate Channel Vulnerability
- 2026-11-18: CVE-2026-90817, Vanderbilt University Research Electronic Data Capture (REDCap): Vanderbilt University Research Electronic Data Capture (REDCap) Code Injection Vulnerability
- 2026-11-18: CVE-2026-90436, Apache Axis: Apache Axis Unsafe Reflection Vulnerability
- 2026-11-17: CVE-2026-115731, Perforce Puppet Enterprise: Perforce Puppet Enterprise Deserialization of Untrusted Data Vulnerability
- 2026-11-13: CVE-2026-114713, UnrealIRCd UnrealIRCd: UnrealIRCd Improper Neutralization of Delimiters Vulnerability
- 2026-11-13: CVE-2026-123039, Check Point Multiple Products: Check Point Multiple Products Incorrect Permission Assignment for Critical Resource Vulnerability

Full data: https://depweather.com/data/latest.json
