# depweather forecast, 2026-11-22

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-11-22T23:36:41Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 16 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 9
- New CVEs in NVD today (UTC): 197
- CVEs published in 2026-11 so far: 12,640 (same month last year: 3,021)

## By ecosystem

### Runtimes & servers

- **Ruby**: 1 advisory, worst actively exploited (CISA KEV); fixed in 3.3.13, 3.4.12, 4.0.8. Example: [BIT-ruby-2026-97229](https://osv.dev/vulnerability/BIT-ruby-2026-97229) Integer Overflow or Wraparound in GitLab
- **WordPress**: 1 advisory, worst actively exploited (CISA KEV); fixed in 4.7.39, 4.8.34, 4.9.35, 5.0.31 and more. Example: [BIT-wordpress-2026-119977](https://osv.dev/vulnerability/BIT-wordpress-2026-119977) WordPress Core 4.7.0 - 7.1.3 - Unauthenticated Upgrade-Window Staged-Installer Remote Code Execution
- **MongoDB**: 1 advisory, worst critical; fixed in 4.4.32, 5.0.35, 6.0.30, 7.0.48 and more. Example: [BIT-mongodb-2026-118383](https://osv.dev/vulnerability/BIT-mongodb-2026-118383) Pre-authentication use-after-free in MongoDB Server replica set primary catch-up
- **Java (OpenJDK) (java)**: 10 advisories, worst high. Example: [DEBIAN-CVE-2026-114940](https://osv.dev/vulnerability/DEBIAN-CVE-2026-114940) Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511b33, 8u511b33-perf, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM
- **Python**: 3 advisories, worst high; fixed in 3.14.11, 3.16.0. Example: [BIT-libpython-2026-119170](https://osv.dev/vulnerability/BIT-libpython-2026-119170) Regression in FIPS enforcement of hash algorithms affecting only Python 3.14.10
- **Apache httpd (apache)**: 1 advisory, worst high; fixed in 2.4.71. Example: [BIT-apache-2026-119618](https://osv.dev/vulnerability/BIT-apache-2026-119618) Apache HTTP Server: mod_http2: heap corruption and RCE in assign_headers
- **MariaDB**: 1 advisory, worst high; fixed in 10.11.19, 11.4.13, 11.8.9, 12.3.3 and more. Example: [BIT-mariadb-2026-102523](https://osv.dev/vulnerability/BIT-mariadb-2026-102523) MariaDB server: Authorization bypass via ALTER TABLE ... CONVERT ... PARTITION

### npm

- **SvelteKit (@sveltejs/kit)**: 4 advisories, worst high; fixed in 3.1.1, 2.70.4. Example: [GHSA-m9j8-jcmv-hp69](https://osv.dev/vulnerability/GHSA-m9j8-jcmv-hp69) SvelteKit: Build-time server-only module import guard could fail, resulting in server secrets being statically replaced in client bundle
- **Next.js (next)**: 7 advisories, worst medium; fixed in 15.5.29, 16.4.5. Example: [GHSA-f3mh-rxg3-f5g2](https://osv.dev/vulnerability/GHSA-f3mh-rxg3-f5g2) Next.js: HttpOnly cookie exposure through internal response header on Next.js Edge runtime routes
- **Nuxt**: 4 advisories, worst medium; fixed in 4.6.4. Example: [GHSA-96x6-fvhx-49hg](https://osv.dev/vulnerability/GHSA-96x6-fvhx-49hg) Nuxt exposes the message and data of unhandled errors thrown during server rendering

### PyPI

- **aiohttp**: 4 advisories, worst high; fixed in 3.14.4. Example: [GHSA-pw86-h8fm-j323](https://osv.dev/vulnerability/GHSA-pw86-h8fm-j323) AIOHTTP: Unbounded buffering of data received during an upgrade request

### Hex

- **Phoenix**: 2 advisories, worst high; fixed in 1.5.16, 1.6.18, 1.7.25, 1.8.17. Example: [EEF-CVE-2026-128361](https://osv.dev/vulnerability/EEF-CVE-2026-128361) Unsanitized presence key crashes Presence tracker
- **LiveView (phoenix_live_view)**: 1 advisory, worst medium; fixed in 1.0.20, 1.1.34, 1.2.14. Example: [EEF-CVE-2026-126334](https://osv.dev/vulnerability/EEF-CVE-2026-126334) Joining a LiveView without `"url"` skips its `live_session` `on_mount` hooks
- **plug**: 1 advisory, worst medium; fixed in 1.20.4. Example: [EEF-CVE-2026-120287](https://osv.dev/vulnerability/EEF-CVE-2026-120287) Multipart `:length` limit not charged for part and header framing in Plug.Parsers.MULTIPART

### crates.io

- **url**: 1 advisory, worst low or unrated; fixed in 2.5.9. Example: [RUSTSEC-2026-0592](https://osv.dev/vulnerability/RUSTSEC-2026-0592) Stack overflow in `Url::origin()` on nested `blob:` URLs

### Packagist

- **Drupal core (drupal/core)**: 2 advisories, worst low or unrated; fixed in 10.6.22, 11.3.22, 11.4.13. Example: [DRUPAL-CORE-2026-018](https://osv.dev/vulnerability/DRUPAL-CORE-2026-018) Drupal core contains a chain of methods that could be exploitable when an insecure deserialization vulnerability exists on the site. This so-called "gadget chain" presents no direct threat, but is a vector that can be used to achieve remote code execution if the application deserializes untrusted da

### Maven

No new advisories for the tracked packages.

### NuGet

No new advisories for the tracked packages.

### Go

No new advisories for the tracked packages.

### RubyGems

No new advisories for the tracked packages.

## Added to CISA KEV this week (all vendors)

- 2026-11-20: CVE-2026-129448, Apache Roller: Apache Roller Deserialization of Untrusted Data Vulnerability
- 2026-11-20: CVE-2026-123890, Broadcom VMware vCenter: VMWare vCenter Authentication Bypass Using an Alternate Path or Channel Vulnerability
- 2026-11-20: CVE-2025-42884, SAP NetWeaver: SAP NetWeaver Improper Neutralization of Special Elements in Data Query Logic Vulnerability
- 2026-11-20: CVE-2026-76466, Cisco Expressway Series: Cisco Expressway Series Use of Hard-coded Credentials Vulnerability
- 2026-11-18: CVE-2024-10441, Synology DiskStation Manager (DSM): Synology DiskStation Manager (DSM) Improper Encoding or Escaping of Output Vulnerability
- 2026-11-18: CVE-2026-40217, BerriAI LiteLLM: BerriAI LiteLLM Unprotected Alternate Channel Vulnerability
- 2026-11-18: CVE-2026-90817, Vanderbilt University Research Electronic Data Capture (REDCap): Vanderbilt University Research Electronic Data Capture (REDCap) Code Injection Vulnerability
- 2026-11-18: CVE-2026-90436, Apache Axis: Apache Axis Unsafe Reflection Vulnerability
- 2026-11-17: CVE-2026-115731, Perforce Puppet Enterprise: Perforce Puppet Enterprise Deserialization of Untrusted Data Vulnerability

Full data: https://depweather.com/data/latest.json
