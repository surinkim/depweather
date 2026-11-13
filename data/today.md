# depweather forecast, 2026-11-13

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-11-13T23:34:48Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 12 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 13
- New CVEs in NVD today (UTC): 792
- CVEs published in 2026-11 so far: 7,800 (same month last year: 3,021)

## By ecosystem

### RubyGems

- **Ruby on Rails (rails)**: 20 advisories, worst critical; fixed in 8.1.4.1, 8.0.5.2. Example: [GHSA-f3w6-w445-fwh9](https://osv.dev/vulnerability/GHSA-f3w6-w445-fwh9) Active Storage: Possible arbitrary file write and read in image analysis
- **rack**: 4 advisories, worst high; fixed in 2.2.25, 3.1.23, 3.2.8. Example: [GHSA-5v64-555j-wjxm](https://osv.dev/vulnerability/GHSA-5v64-555j-wjxm) Rack: Multipart parsing allows DoS via unbounded scan buffer growth
- **nokogiri**: 3 advisories, worst low or unrated; fixed in 1.19.5. Example: [GHSA-v995-44v6-5fqm](https://osv.dev/vulnerability/GHSA-v995-44v6-5fqm) JRuby: NONET is bypassed for external DTDs and entities when the systemId uses a short-form IPv4 host

### PyPI

- **pillow**: 2 advisories, worst high; fixed in 13.0.0. Example: [GHSA-xcvg-w56q-r89m](https://osv.dev/vulnerability/GHSA-xcvg-w56q-r89m) Pillow: Heap buffer overflow saving TIFF with libtiff when tags override image size

### NuGet

- **ASP.NET Core (Microsoft.AspNetCore.App.Runtime.linux-x64)**: 13 advisories, worst high; fixed in 2.3.14, 8.0.34, 9.0.23, 10.0.15 and more. Example: [GHSA-wr8v-9x5q-ggcm](https://osv.dev/vulnerability/GHSA-wr8v-9x5q-ggcm) Microsoft Security Advisory CVE-2026-114147 - ASP.NET Core Denial of Service Vulnerability
- **.NET runtime (Microsoft.NETCore.App.Runtime.linux-x64)**: 7 advisories, worst high; fixed in 8.0.34, 9.0.23, 10.0.15, 11.0.0. Example: [GHSA-x8x8-p968-x646](https://osv.dev/vulnerability/GHSA-x8x8-p968-x646) Microsoft Security Advisory CVE-2026-118745 - Visual Studio Remote Code Execution Vulnerability
- **System.Text.Json**: 1 advisory, worst medium; fixed in 11.0.0. Example: [GHSA-cpw3-h88j-9f6x](https://osv.dev/vulnerability/GHSA-cpw3-h88j-9f6x) Microsoft Security Advisory CVE-2026-120796 - .NET Denial of Service Vulnerability

### npm

- **Hono**: 5 advisories, worst medium; fixed in 4.13.16. Example: [GHSA-46wx-v44x-9hh2](https://osv.dev/vulnerability/GHSA-46wx-v44x-9hh2) Hono: `csrf()` does not check requests sent by hyperlink auditing (`text/ping`)
- **Astro**: 2 advisories, worst medium; fixed in 7.4.5, 7.4.7. Example: [GHSA-r3h5-4585-7x3w](https://osv.dev/vulnerability/GHSA-r3h5-4585-7x3w) Astro: Image endpoint in @astrojs/node can read files from a case-variant sibling of the output directory on case-sensitive filesystems
- **SvelteKit (@sveltejs/kit)**: 1 advisory, worst medium; fixed in 3.1.1, 2.70.4. Example: [GHSA-mw6w-2fmv-pvw3](https://osv.dev/vulnerability/GHSA-mw6w-2fmv-pvw3) SvelteKit: adapter-node crashes with an unhandled URIError when `reroute` rewrites malformed pathnames

### Packagist

- **Laravel (laravel/framework)**: 1 advisory, worst low or unrated; fixed in 12.71.0, 13.40.0. Example: [GHSA-63hm-g96r-2m2q](https://osv.dev/vulnerability/GHSA-63hm-g96r-2m2q) Laravel: Task Output Injection - Concurrency Process

### Go

- **Go stdlib (stdlib)**: 1 advisory, worst low or unrated; fixed in 1.26.11, 1.27.4. Example: [GO-2026-6859](https://osv.dev/vulnerability/GO-2026-6859) HTTP/1 server crash due to MaxBytesReader header race in net/http

### Maven

No new advisories for the tracked packages.

### crates.io

No new advisories for the tracked packages.

### Hex

No new advisories for the tracked packages.

### Runtimes & servers

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
- 2026-11-09: CVE-2026-102895, GPUStack GPUStack: GPUStack Improper Authentication Vulnerability
- 2026-11-09: CVE-2026-123158, OpenBSD OpenSSH: OpenBSD OpenSSH Unexpected Status Code or Return Value Vulnerability
- 2026-11-09: CVE-2026-116779, SignalWire FreeSwitch: SignalWire FreeSwitch Code Injection Vulnerability
- 2026-11-09: CVE-2026-123218, IBM Aspera Faspex: IBM Aspera Faspex Incorrect Authorization Vulnerability
- 2026-11-06: CVE-2026-19868, SonicWall SonicOS SSLVPN: SonicWall SonicOS SSLVPN Use of Single-factor Authentication Vulnerability

Full data: https://depweather.com/data/latest.json
