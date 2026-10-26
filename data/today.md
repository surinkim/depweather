# depweather forecast, 2026-10-26

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-10-26T22:41:04Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 24 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 8
- New CVEs in NVD today (UTC): 732
- CVEs published in 2026-10 so far: 14,463 (same month last year: 4,273)

## By ecosystem

### npm

- **Next.js (next)**: 4 advisories, worst critical; fixed in 16.4.1, 16.3.8, 15.5.28. Example: [GHSA-673q-mjm6-r5xr](https://osv.dev/vulnerability/GHSA-673q-mjm6-r5xr) Next.js: Unauthenticated Remote Code Execution in `use cache` functions returning typed arrays
- **vite**: 6 advisories, worst high; fixed in 8.3.3, 8.2.4, 8.1.6, 7.3.7 and more. Example: [GHSA-587h-7wmj-h5pm](https://osv.dev/vulnerability/GHSA-587h-7wmj-h5pm) launch-editor: `fs.existsSync()` existence check can be bypassed on Windows
- **undici**: 3 advisories, worst high; fixed in 6.29.1, 7.30.1, 8.12.2. Example: [GHSA-xjj6-f33q-929c](https://osv.dev/vulnerability/GHSA-xjj6-f33q-929c) undici vulnerable to Denial of Service via unhandled error on excessive content-encodings
- **Nuxt**: 4 advisories, worst medium; fixed in 4.6.2, 4.6.0, 4.4.4, 3.21.4. Example: [GHSA-vjh5-4x84-xrqp](https://osv.dev/vulnerability/GHSA-vjh5-4x84-xrqp) Nuxt: Server-side route rules (`redirect`, `headers`, `proxy`, `ssr`) are skipped for case-variant paths when routing is case-insensitive
- **Astro**: 2 advisories, worst medium; fixed in 7.3.2, 7.3.3. Example: [GHSA-98hj-9722-w3j8](https://osv.dev/vulnerability/GHSA-98hj-9722-w3j8) Astro: Reflected/Stored XSS via unescaped <script>/<style> tag content in JSX/MDX rendering
- **SvelteKit (@sveltejs/kit)**: 2 advisories, worst medium; fixed in 3.0.0. Example: [GHSA-pfhg-q3qv-9q6r](https://osv.dev/vulnerability/GHSA-pfhg-q3qv-9q6r) SvelteKit: URL redirection to untrusted site via enhanced form submission
- **Hono**: 1 advisory, worst medium; fixed in 4.13.11. Example: [GHSA-5r4p-p66f-jhc7](https://osv.dev/vulnerability/GHSA-5r4p-p66f-jhc7) Hono: `serveStatic` decodes the request path a second time, leading to bypass of middleware on static paths
- **Fastify**: 1 advisory, worst low or unrated; fixed in 5.12.6. Example: [GHSA-389g-gv7q-r4x8](https://osv.dev/vulnerability/GHSA-389g-gv7q-r4x8) fastify is vulnerable to header validation bypass via case-sensitive propertyNames

### PyPI

- **pillow**: 41 advisories, worst critical; fixed in 13.0.0. Example: [GHSA-5x8w-8jj5-q52h](https://osv.dev/vulnerability/GHSA-5x8w-8jj5-q52h) Pillow: Heap buffer overflow in FlashPix (FPX) JPEG decoding leads to code execution
- **certifi**: 1 advisory, worst critical; fixed in 2026.10.18, 2026.10.19. Example: [GHSA-6q48-6c7w-9gw2](https://osv.dev/vulnerability/GHSA-6q48-6c7w-9gw2) certifi bundles emSign root CAs with compromised intermediate CA keys
- **aiohttp**: 5 advisories, worst high; fixed in 3.14.4. Example: [GHSA-9xw5-w5jj-pvcg](https://osv.dev/vulnerability/GHSA-9xw5-w5jj-pvcg) AIOHTTP: File descriptor exhaustion in multipart requests
- **pyjwt**: 1 advisory, worst high; fixed in 2.14.0. Example: [GHSA-pxh4-856f-4h89](https://osv.dev/vulnerability/GHSA-pxh4-856f-4h89) PyJWT: HS256/384/512 verify accepts empty HMAC key via oct JWK (PyJWK/PyJWKClient) enabling token forgery
- **setuptools**: 1 advisory, worst low or unrated; fixed in 84.1.0. Example: [GHSA-xmj3-9gf7-h52w](https://osv.dev/vulnerability/GHSA-xmj3-9gf7-h52w) setuptools: Windows path escape via namespace_packages.txt during legacy wheel installation  Description

### Packagist

- **Laravel (laravel/framework)**: 2 advisories, worst critical; fixed in 13.29.0, 12.68.0, 13.27.0. Example: [GHSA-f9x3-7vq9-cph6](https://osv.dev/vulnerability/GHSA-f9x3-7vq9-cph6) Laravel TokenGuard authentication bypass through non-string API credentials

### Go

- **Echo (github.com/labstack/echo/v4)**: 4 advisories, worst critical; fixed in 4.16.1. Example: [GHSA-cxf3-9h37-7rr8](https://osv.dev/vulnerability/GHSA-cxf3-9h37-7rr8) Echo: Rejected WebSocket upgrades can bypass Echo route-level access controls
- **Go stdlib (stdlib)**: 1 advisory, worst low or unrated; fixed in 1.26.10, 1.27.3. Example: [GO-2026-6809](https://osv.dev/vulnerability/GO-2026-6809) Distrust compromised intermediate certificates in crypto/x509

### Hex

- **hackney**: 5 advisories, worst critical; fixed in 4.9.0. Example: [EEF-CVE-2026-115693](https://osv.dev/vulnerability/EEF-CVE-2026-115693) Custom cacerts or cacertfile do not restrict trust to the pinned CA in hackney
- **plug**: 1 advisory, worst medium; fixed in 1.7.0. Example: [EEF-CVE-2026-105963](https://osv.dev/vulnerability/EEF-CVE-2026-105963) Secret key base exposed in stack trace arguments on wrong-typed Plug.Crypto arguments

### Runtimes & servers

- **MariaDB**: 7 advisories, worst critical; fixed in 10.6.28, 10.11.19, 11.4.13, 11.8.9 and more. Example: [BIT-mariadb-2026-92262](https://osv.dev/vulnerability/BIT-mariadb-2026-92262) MariaDB: Numerous issues caused by historical #mysql50# tablename encoding bypass.
- **nginx**: 5 advisories, worst critical; fixed in 1.30.6, 1.31.7, 1.29.0. Example: [BIT-nginx-2026-97205](https://osv.dev/vulnerability/BIT-nginx-2026-97205) NGINX ngx_http_core_module vulnerability
- **PHP**: 2 advisories, worst critical; fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12. Example: [BIT-libphp-2026-109619](https://osv.dev/vulnerability/BIT-libphp-2026-109619) RCE via stale global state
- **Node.js (node)**: 1 advisory, worst critical; fixed in 22.23.4, 24.22.1, 26.12.1. Example: [BIT-node-2026-111497](https://osv.dev/vulnerability/BIT-node-2026-111497) A flaw in Node.js can cause Node.js Brotli decoder out-of-bounds write permits remote code execution. This vulnerability affects Node.js 22.x, 24.x, and 26.x.

### crates.io

- **tokio**: 1 advisory, worst medium; fixed in 1.54.1. Example: [GHSA-5wjr-9356-4wc8](https://osv.dev/vulnerability/GHSA-5wjr-9356-4wc8) Tokio: Race condition in `tokio::time::Interval`
- **rustls**: 1 advisory, worst low or unrated; fixed in 0.103.16, 0.104.0-alpha.8. Example: [RUSTSEC-2026-0382](https://osv.dev/vulnerability/RUSTSEC-2026-0382) Certificate verification may accept distrusted intermediates

### Maven

No new advisories for the tracked packages.

### NuGet

No new advisories for the tracked packages.

### RubyGems

No new advisories for the tracked packages.

## Added to CISA KEV this week (all vendors)

- 2026-10-23: CVE-2026-114625, Arista VeloCloud Orchestrator: Arista VeloCloud Orchestrator SQL Injection Vulnerability
- 2026-10-23: CVE-2026-110447, Collabora Collabora Online – Built-in CODE Server: Collabora Online – Built-in CODE Server OS Command Injection Vulnerability
- 2026-10-20: CVE-2026-106931, EG Secure Solutions SiteGuard Server Edition: EG Secure Solutions SiteGuard Server Edition OS Command Injection Vulnerability
- 2026-10-20: CVE-2026-96656, Plex Media Server: Plex Media Server External Control of File Name or Path Vulnerability
- 2026-10-20: CVE-2026-96655, Plex Media Server: Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability
- 2026-10-20: CVE-2026-96654, Plex Media Server: Plex Media Server Improper Neutralization of Encoded URI Schemes in a Web Page Vulnerability
- 2026-10-20: CVE-2026-96652, Plex Media Server: Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability
- 2026-10-20: CVE-2026-110936, Siemens Software Center: Siemens Software Center Uncontrolled Search Path Element Vulnerability

Full data: https://depweather.com/data/latest.json
