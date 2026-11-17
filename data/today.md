# depweather forecast, 2026-11-17

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-11-17T15:57:25Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 21 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 8
- New CVEs in NVD today (UTC): 187
- CVEs published in 2026-11 so far: 8,518 (same month last year: 3,021)

## By ecosystem

### Runtimes & servers

- **Ruby**: 1 advisory, worst actively exploited (CISA KEV); fixed in 3.3.13, 3.4.12, 4.0.8. Example: [BIT-ruby-2026-97229](https://osv.dev/vulnerability/BIT-ruby-2026-97229) Integer Overflow or Wraparound in GitLab
- **WordPress**: 1 advisory, worst actively exploited (CISA KEV); fixed in 4.7.39, 4.8.34, 4.9.35, 5.0.31 and more. Example: [BIT-wordpress-2026-119977](https://osv.dev/vulnerability/BIT-wordpress-2026-119977) WordPress Core 4.7.0 - 7.1.3 - Unauthenticated Upgrade-Window Staged-Installer Remote Code Execution
- **MongoDB**: 1 advisory, worst critical; fixed in 4.4.32, 5.0.35, 6.0.30, 7.0.48 and more. Example: [BIT-mongodb-2026-118383](https://osv.dev/vulnerability/BIT-mongodb-2026-118383) Pre-authentication use-after-free in MongoDB Server replica set primary catch-up
- **Python**: 3 advisories, worst high; fixed in 3.14.11, 3.16.0. Example: [BIT-libpython-2026-119170](https://osv.dev/vulnerability/BIT-libpython-2026-119170) Regression in FIPS enforcement of hash algorithms affecting only Python 3.14.10
- **Apache httpd (apache)**: 1 advisory, worst high; fixed in 2.4.71. Example: [BIT-apache-2026-119618](https://osv.dev/vulnerability/BIT-apache-2026-119618) Apache HTTP Server: mod_http2: heap corruption and RCE in assign_headers
- **MariaDB**: 1 advisory, worst high; fixed in 10.11.19, 11.4.13, 11.8.9, 12.3.3 and more. Example: [BIT-mariadb-2026-102523](https://osv.dev/vulnerability/BIT-mariadb-2026-102523) MariaDB server: Authorization bypass via ALTER TABLE ... CONVERT ... PARTITION

### RubyGems

- **Ruby on Rails (rails)**: 20 advisories, worst critical; fixed in 8.1.4.1, 8.0.5.2. Example: [GHSA-f3w6-w445-fwh9](https://osv.dev/vulnerability/GHSA-f3w6-w445-fwh9) Active Storage: Possible arbitrary file write and read in image analysis
- **rack**: 4 advisories, worst high; fixed in 2.2.25, 3.1.23, 3.2.8. Example: [GHSA-5v64-555j-wjxm](https://osv.dev/vulnerability/GHSA-5v64-555j-wjxm) Rack: Multipart parsing allows DoS via unbounded scan buffer growth
- **nokogiri**: 3 advisories, worst low or unrated; fixed in 1.19.5. Example: [GHSA-v995-44v6-5fqm](https://osv.dev/vulnerability/GHSA-v995-44v6-5fqm) JRuby: NONET is bypassed for external DTDs and entities when the systemId uses a short-form IPv4 host

### npm

- **SvelteKit (@sveltejs/kit)**: 5 advisories, worst high; fixed in 3.1.1, 2.70.4. Example: [GHSA-m9j8-jcmv-hp69](https://osv.dev/vulnerability/GHSA-m9j8-jcmv-hp69) SvelteKit: Build-time server-only module import guard could fail, resulting in server secrets being statically replaced in client bundle
- **Hono**: 5 advisories, worst medium; fixed in 4.13.16. Example: [GHSA-46wx-v44x-9hh2](https://osv.dev/vulnerability/GHSA-46wx-v44x-9hh2) Hono: `csrf()` does not check requests sent by hyperlink auditing (`text/ping`)
- **Nuxt**: 4 advisories, worst medium; fixed in 4.6.4. Example: [GHSA-96x6-fvhx-49hg](https://osv.dev/vulnerability/GHSA-96x6-fvhx-49hg) Nuxt exposes the message and data of unhandled errors thrown during server rendering
- **Astro**: 2 advisories, worst medium; fixed in 7.4.5, 7.4.7. Example: [GHSA-r3h5-4585-7x3w](https://osv.dev/vulnerability/GHSA-r3h5-4585-7x3w) Astro: Image endpoint in @astrojs/node can read files from a case-variant sibling of the output directory on case-sensitive filesystems
- **Next.js (next)**: 1 advisory, worst medium; fixed in 16.4.5. Example: [GHSA-mfr8-8qww-v76h](https://osv.dev/vulnerability/GHSA-mfr8-8qww-v76h) Next.js: Information disclosure across root params when a 'use cache' function is called through unstable_cache()

### PyPI

- **aiohttp**: 9 advisories, worst high; fixed in 3.14.4. Example: [GHSA-jm3w-gw2p-xjfj](https://osv.dev/vulnerability/GHSA-jm3w-gw2p-xjfj) AIOHTTP: Event loop stall in add_domain() wildcard matching
- **pillow**: 2 advisories, worst high; fixed in 13.0.0. Example: [GHSA-xcvg-w56q-r89m](https://osv.dev/vulnerability/GHSA-xcvg-w56q-r89m) Pillow: Heap buffer overflow saving TIFF with libtiff when tags override image size

### NuGet

- **ASP.NET Core (Microsoft.AspNetCore.App.Runtime.linux-x64)**: 13 advisories, worst high; fixed in 2.3.14, 8.0.34, 9.0.23, 10.0.15 and more. Example: [GHSA-wr8v-9x5q-ggcm](https://osv.dev/vulnerability/GHSA-wr8v-9x5q-ggcm) Microsoft Security Advisory CVE-2026-114147 - ASP.NET Core Denial of Service Vulnerability
- **.NET runtime (Microsoft.NETCore.App.Runtime.linux-x64)**: 7 advisories, worst high; fixed in 8.0.34, 9.0.23, 10.0.15, 11.0.0. Example: [GHSA-x8x8-p968-x646](https://osv.dev/vulnerability/GHSA-x8x8-p968-x646) Microsoft Security Advisory CVE-2026-118745 - Visual Studio Remote Code Execution Vulnerability
- **System.Text.Json**: 1 advisory, worst medium; fixed in 11.0.0. Example: [GHSA-cpw3-h88j-9f6x](https://osv.dev/vulnerability/GHSA-cpw3-h88j-9f6x) Microsoft Security Advisory CVE-2026-120796 - .NET Denial of Service Vulnerability

### Go

- **Go stdlib (stdlib)**: 1 advisory, worst medium; fixed in 1.26.11, 1.27.4. Example: [GO-2026-6859](https://osv.dev/vulnerability/GO-2026-6859) HTTP/1 server crash due to MaxBytesReader header race in net/http

### Packagist

- **Laravel (laravel/framework)**: 1 advisory, worst low or unrated; fixed in 12.71.0, 13.40.0. Example: [GHSA-63hm-g96r-2m2q](https://osv.dev/vulnerability/GHSA-63hm-g96r-2m2q) Laravel: Task Output Injection - Concurrency Process

### Maven

No new advisories for the tracked packages.

### crates.io

No new advisories for the tracked packages.

### Hex

No new advisories for the tracked packages.

## Added to CISA KEV this week (all vendors)

- 2026-11-13: CVE-2026-114713, UnrealIRCd UnrealIRCd: UnrealIRCd Improper Neutralization of Delimiters Vulnerability
- 2026-11-13: CVE-2026-123039, Check Point Multiple Products: Check Point Multiple Products Incorrect Permission Assignment for Critical Resource Vulnerability
- 2026-11-10: CVE-2026-124194, Microsoft Office: Microsoft Office Outlook Missing User Interaction for Potentially Unsafe Action Vulnerability
- 2026-11-10: CVE-2026-111793, Openwave Messaging Limited Webtop Media Transcoder: Openwave Messaging Limited Webtop Media Transcoder Incorrect Resource Transfer Between Spheres Vulnerability
- 2026-11-10: CVE-2026-20320, Cisco BroadWorks: Cisco BroadWorks Improper Restriction of XML External Entity Reference Vulnerability
- 2026-11-10: CVE-2026-111560, Barracuda Networks Multiple Products: Barracuda Networks Multiple Products OS Command Injection Vulnerability
- 2026-11-10: CVE-2026-116606, Barracuda Networks Barracuda Email Security Gateway (ESG): Barracuda Networks Email Security Gateway (ESG) Authentication Bypass Using an Alternate Path or Channel Vulnerability
- 2026-11-10: CVE-2026-125350, Google Chromium: Google Chromium Use-After-Free Vulnerability

Full data: https://depweather.com/data/latest.json
