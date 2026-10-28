# depweather forecast, 2026-10-28

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-10-28T12:50:58Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 19 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 6
- New CVEs in NVD today (UTC): 324
- CVEs published in 2026-10 so far: 15,441 (same month last year: 4,273)

## By ecosystem

### Runtimes & servers

- **PHP**: 2 advisories, worst actively exploited (CISA KEV); fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12. Example: [BIT-libphp-2026-109619](https://osv.dev/vulnerability/BIT-libphp-2026-109619) RCE via stale global state
- **Node.js (node)**: 1 advisory, worst actively exploited (CISA KEV); fixed in 22.23.4, 24.22.1, 26.12.1. Example: [BIT-node-2026-111497](https://osv.dev/vulnerability/BIT-node-2026-111497) A flaw in Node.js can cause Node.js Brotli decoder out-of-bounds write permits remote code execution. This vulnerability affects Node.js 22.x, 24.x, and 26.x.

### npm

- **Next.js (next)**: 4 advisories, worst critical; fixed in 16.4.1, 16.3.8, 15.5.28. Example: [GHSA-673q-mjm6-r5xr](https://osv.dev/vulnerability/GHSA-673q-mjm6-r5xr) Next.js: Unauthenticated Remote Code Execution in `use cache` functions returning typed arrays
- **undici**: 9 advisories, worst high; fixed in 7.30.1, 8.12.2, 6.29.1, 8.11.2. Example: [GHSA-4w7w-5xrc-9h26](https://osv.dev/vulnerability/GHSA-4w7w-5xrc-9h26) undici vulnerable to cache poisoning and cross-user disclosure via cross-origin redirects
- **Nuxt**: 4 advisories, worst medium; fixed in 4.6.2, 4.6.0, 4.4.4, 3.21.4. Example: [GHSA-vjh5-4x84-xrqp](https://osv.dev/vulnerability/GHSA-vjh5-4x84-xrqp) Nuxt: Server-side route rules (`redirect`, `headers`, `proxy`, `ssr`) are skipped for case-variant paths when routing is case-insensitive
- **vite**: 3 advisories, worst medium; fixed in 8.3.3, 8.2.4, 8.1.6, 7.3.7 and more. Example: [GHSA-rq7h-c2jc-7f22](https://osv.dev/vulnerability/GHSA-rq7h-c2jc-7f22) Vite: Files outside `server.fs.allow` could be served when project paths match system paths on non-Windows machine
- **Astro**: 2 advisories, worst medium; fixed in 7.3.2, 7.3.3. Example: [GHSA-98hj-9722-w3j8](https://osv.dev/vulnerability/GHSA-98hj-9722-w3j8) Astro: Reflected/Stored XSS via unescaped <script>/<style> tag content in JSX/MDX rendering
- **SvelteKit (@sveltejs/kit)**: 2 advisories, worst medium; fixed in 3.0.0. Example: [GHSA-pfhg-q3qv-9q6r](https://osv.dev/vulnerability/GHSA-pfhg-q3qv-9q6r) SvelteKit: URL redirection to untrusted site via enhanced form submission
- **Fastify**: 1 advisory, worst low or unrated; fixed in 5.12.6. Example: [GHSA-389g-gv7q-r4x8](https://osv.dev/vulnerability/GHSA-389g-gv7q-r4x8) fastify is vulnerable to header validation bypass via case-sensitive propertyNames

### PyPI

- **pillow**: 25 advisories, worst critical; fixed in 13.0.0. Example: [GHSA-332p-7hrc-92wf](https://osv.dev/vulnerability/GHSA-332p-7hrc-92wf) Pillow: Heap buffer overflow in _tiffWriteProc when saving TIFF to BytesIO
- **pyjwt**: 1 advisory, worst high; fixed in 2.14.0. Example: [GHSA-pxh4-856f-4h89](https://osv.dev/vulnerability/GHSA-pxh4-856f-4h89) PyJWT: HS256/384/512 verify accepts empty HMAC key via oct JWK (PyJWK/PyJWKClient) enabling token forgery
- **setuptools**: 1 advisory, worst low or unrated; fixed in 84.1.0. Example: [GHSA-xmj3-9gf7-h52w](https://osv.dev/vulnerability/GHSA-xmj3-9gf7-h52w) setuptools: Windows path escape via namespace_packages.txt during legacy wheel installation  Description

### Packagist

- **Laravel (laravel/framework)**: 2 advisories, worst critical; fixed in 13.29.0, 12.68.0, 13.27.0. Example: [GHSA-f9x3-7vq9-cph6](https://osv.dev/vulnerability/GHSA-f9x3-7vq9-cph6) Laravel TokenGuard authentication bypass through non-string API credentials
- **Symfony (symfony/http-kernel)**: 2 advisories, worst high; fixed in 5.4.54, 6.4.45, 7.4.18, 8.1.6 and more. Example: [GHSA-2v3c-qxhr-7vpv](https://osv.dev/vulnerability/GHSA-2v3c-qxhr-7vpv) Symfony: Unbounded Recursion in the YAML Inline Lexer Lets a Single Document Crash the Process

### Go

- **Echo (github.com/labstack/echo/v4)**: 4 advisories, worst critical; fixed in 4.16.1. Example: [GHSA-cxf3-9h37-7rr8](https://osv.dev/vulnerability/GHSA-cxf3-9h37-7rr8) Echo: Rejected WebSocket upgrades can bypass Echo route-level access controls
- **x/net (golang.org/x/net)**: 2 advisories, worst low or unrated; fixed in 0.62.0. Example: [GO-2026-6866](https://osv.dev/vulnerability/GO-2026-6866) Check all ancestor namespace transitions when rendering raw text in html in golang.org/x/net

### Hex

- **hackney**: 5 advisories, worst critical; fixed in 4.9.0. Example: [EEF-CVE-2026-115693](https://osv.dev/vulnerability/EEF-CVE-2026-115693) Custom cacerts or cacertfile do not restrict trust to the pinned CA in hackney
- **plug**: 1 advisory, worst medium; fixed in 1.7.0. Example: [EEF-CVE-2026-105963](https://osv.dev/vulnerability/EEF-CVE-2026-105963) Secret key base exposed in stack trace arguments on wrong-typed Plug.Crypto arguments

### Maven

- **guava (com.google.guava:guava)**: 1 advisory, worst high; fixed in 33.7.2. Example: [GHSA-xxph-c9ww-hj94](https://osv.dev/vulnerability/GHSA-xxph-c9ww-hj94) Google Guava: CompactHashMap/CompactHashSet/MapMakerInternalMap deserialization triggers uncontrolled memory allocation

### NuGet

No new advisories for the tracked packages.

### crates.io

No new advisories for the tracked packages.

### RubyGems

No new advisories for the tracked packages.

## Added to CISA KEV this week (all vendors)

- 2026-10-27: CVE-2026-48356, Adobe Commerce and Magento: Adobe Commerce and Magento Unrestricted Upload of File with Dangerous Type Vulnerability
- 2026-10-27: CVE-2026-111497, Google Brotli: Google Brotli Unchecked Return Value Vulnerability
- 2026-10-26: CVE-2026-109618, PHP Group PHP: PHP Memory Corruption Vulnerability
- 2026-10-26: CVE-2026-109619, PHP Group PHP: PHP Stale Internal Request-State Vulnerability
- 2026-10-23: CVE-2026-114625, Arista VeloCloud Orchestrator: Arista VeloCloud Orchestrator SQL Injection Vulnerability
- 2026-10-23: CVE-2026-110447, Collabora Collabora Online – Built-in CODE Server: Collabora Online – Built-in CODE Server OS Command Injection Vulnerability

Full data: https://depweather.com/data/latest.json
