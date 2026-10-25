# How depweather works

**English** | [한국어](how-it-works.ko.md) · [Back to README](../README.md)

The details behind the page: what each view shows, how color and severity are decided, how packages are picked, and where the data comes from.

## What it shows

**Numbers on top**

| Number | Meaning |
|---|---|
| New CVEs today | CVEs published in NVD since 00:00 UTC (rejected CVEs excluded) |
| CVEs this month | NVD CVEs published this month so far, and the change against the same month last year (whole month) |
| New in CISA KEV, 7 days | Entries added to the KEV catalog in the last 7 days, any vendor |
| Popular packages affected | Tracked packages with at least one advisory published in the last 7 days |

**A. Treemap (default view).** One outlined group per ecosystem: npm, PyPI,
Maven, NuGet, crates.io, Packagist, Go, RubyGems, Hex, plus "Runtimes &
servers" (149 packages). A group's area
is the share of [Stack Overflow Developer Survey 2026](https://survey.stackoverflow.co/2026/technology/data)
respondents who use its language (JavaScript 62.0%, Python 58.0%, Java 27.6%,
C# 27.1%, Rust 18.0%, PHP 17.7%, Go 16.5%, Ruby 5.8%, Elixir 2.6%), with a
3.5% floor so small groups stay findable. "Runtimes & servers" maps to no
single language and has a fixed area (`area: 20` in `stacks.yml`). Inside a group, tile size is the
package's downloads (see "Data sources"; Maven, NuGet, Go and "Runtimes &
servers" use equal weights). Tile color is the worst advisory *published* in the last 7 days
(toggle: 30 days). "KEV only" keeps only advisories whose CVE is in the CISA
KEV catalog.

The treemap fills most of the window height on large screens and has a
"Full screen" button. It zooms: pinch, Ctrl/⌘ + scroll, double-click (Shift +
double-click zooms out), the +/− buttons, or the +/−/0 keys; drag to pan. Text stays the
same size on screen, so a tile shows more as it grows: name → advisory count →
counts by severity and fixed versions → the worst advisory with its summary,
plus downloads and the survey share.

**C. Timeline.** Click a tile or search a package: every advisory of the last
30 days is a dot on the day it was published, with the fixed versions on the
right and a table of advisories below. Default view on screens narrower than
768px.

**B. Counter (option).** Monthly NVD CVE counts for the last 14 months, a
7-day table per ecosystem (new / critical / KEV), and this week's KEV
additions. Overall CVE counts are what [cve.icu](https://cve.icu) already does
well; this view is a side panel, not the point.

The interface is in English or Korean (EN / KO at the top right; the first
visit follows the browser language). Advisory text from the data stays in
English.

The view is kept in the URL (`?view=a|b|c`, `?pkg=npm/next`, `&range=30`,
`&kev=1`, `&lang=ko`) so links can be shared. The last view, period, language
and theme are remembered in `localStorage`. The footer shows the page version,
which helps spot a stale copy in the browser cache (reload with Cmd/Ctrl +
Shift + R).

## Colors and weather

The page reads like a weather report. A sentence at the top is written from
the data ("Storms over npm, PyPI and 3 more, with critical issues in pillow,
MariaDB, nginx and 6 more."), and a strip below it gives each group the
weather of its worst package; clicking a group zooms the map to it.

| Weather | Color | Meaning |
|---|---|---|
| Clear (sun) | Gray tile | No advisory in the period |
| Cloudy (cloud) | Yellow | Low or medium, or no severity given by any source |
| Rain (cloud with rain) | Orange | High |
| Storm (cloud with lightning) | Red | Critical, or a malicious-package report (OSV `MAL-`) |
| Exploited (magenta storm cloud) | Magenta | The CVE is in CISA KEV |

Affected tiles carry the glyph, and timeline dots change shape with severity
(circle, triangle, diamond), so severity never depends on color alone.

Severity is taken in this order: the GitHub Advisory severity label → a CVSS
v3 score computed from the OSV vector → the NVD CVSS base severity (looked up
only for advisories still unrated, e.g. Go standard library entries) →
"unknown" (shown yellow). When OSV lists the same issue under several IDs
(`GO-`, `PYSEC-`, `GHSA-`), they are merged and the highest severity wins.

EPSS is shown in the tooltip and table. An optional rule raises a vulnerability
one color step when its EPSS score is high; it is off by default and controlled
by the constant `EPSS_BUMP_THRESHOLD` at the top of the script in `index.html`
(e.g. `0.1`).

## Packages

The default list in [`collect/stacks.yml`](../collect/stacks.yml) has 149
packages: 136 from language registries and 13 runtimes and servers. Each
ecosystem gets roughly as many as its language's survey share suggests (npm
and PyPI 24, Maven 18, NuGet/crates.io/Packagist/Go 14, RubyGems 8, Hex 6). They are picked in this order:

1. **Frameworks people say they use.** Every entry of the Stack Overflow 2026
   "Web frameworks and technologies" list with at least 2% of respondents,
   when it ships as a package in an OSV ecosystem (React 41.5%, Next.js 20.6%,
   ASP.NET Core 19.9%, jQuery 19.7%, FastAPI 18.5%, Vue.js 17.2%, Angular 16.0%,
   Express 15.6%, Spring Boot 12.8%, Flask 12.5%, Django 11.3%, Svelte,
   Laravel, Blazor, Astro, AngularJS, NestJS, Ruby on Rails, SvelteKit, htmx,
   Nuxt, Deno, Symfony, Axum, Fastify, Hono, Phoenix, Drupal). The share is
   stored as `survey:` and shown on the tile.
2. **Most-downloaded packages of the registry**, where a ranking is public:
   [top-pypi-packages](https://github.com/hugovk/top-pypi-packages) (PyPI),
   crates.io recent downloads, Packagist "popular", hex.pm recent downloads.
   Type stubs, polyfills, platform shims (`windows_*` crates) and test-only
   tools are skipped.
3. **Where no ranking is public** (npm, Maven, Go, NuGet, RubyGems): widely
   used libraries with a history of advisories (HTTP, parsing, crypto, auth,
   serialization), chosen by hand. The daily run records real downloads for
   npm, PyPI, crates.io, Packagist, RubyGems and Hex, so these picks can be
   checked against data and replaced.

**Runtimes and servers** (PHP, Node.js, Python, Java, Ruby, WordPress, nginx,
Apache httpd, Tomcat, PostgreSQL, MariaDB, Redis, MongoDB) come from OSV's
Bitnami ecosystem, which tracks them per container image. Their advisories are
not in the language registries: PHP2Shell (CVE-2026-109618 and
CVE-2026-109619, October 2026) is a flaw in PHP itself, so it shows on the
PHP tile, not in the Packagist group.

Some products are filed in OSV under many package names. A tile can match
several names or name prefixes (`match:` in `stacks.yml`): ASP.NET Core covers
`Microsoft.AspNetCore.*` (including the per-platform runtime packs), .NET
covers `Microsoft.NETCore.App.Runtime.*`, Symfony covers `symfony/*`, Ruby on
Rails covers `actionpack`, `activerecord`, `activestorage` and the other Rails
gems.

The list only holds widely used packages; it should not hint at any company's
stack. Additions are welcome as pull requests. To track a personal list
without committing it, point the collector at another file:

```sh
DEPWEATHER_STACKS=~/my-stacks.yml python collect/collect.py
```

Not covered yet:

- **OpenSSL and other system libraries.** Not in OSV's Bitnami data; covering
  them needs NVD CPE matching or a Linux distribution feed. Kubernetes is
  tracked as the Go module `k8s.io/kubernetes`.
- **Classic ASP.NET (.NET Framework).** Not a package in an OSV ecosystem.
- **Swift (SwiftURL) and Dart (Pub).** OSV has few advisories for them so far.
- **Search beyond the list.** Search only finds tracked packages for now.
- **Security fixes without a CVE** (release notes), from the planning notes.

## Data sources and licenses

| Source | Used for | How | Terms |
|---|---|---|---|
| [OSV.dev](https://osv.dev) | Advisories, affected and fixed versions, aliases | Per-ecosystem export on `osv-vulnerabilities.storage.googleapis.com` (`modified_id.csv`, then one JSON per entry changed in the window) | Records keep the license of their upstream database. **To confirm**: the OSV data license page, not reachable from the environment this was written in |
| [Bitnami Vulnerability Database](https://github.com/bitnami/vulndb) | Runtimes & servers group, via OSV | — | Apache License 2.0 (README of `bitnami/vulndb`, checked 2026-10-25) |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Most npm / PyPI / Maven / Go advisories, via OSV | — | CC-BY 4.0 (`LICENSE.md` in the repository, checked 2026-10-25). Attribution in the page footer |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited flag, 7-day additions | `known_exploited_vulnerabilities.json`, falling back to CISA's GitHub mirror `cisagov/kev-data` | CC0 1.0. From the `cisagov/kev-data` LICENSE (checked 2026-10-25): "The KEV database is distributed under the Creative Commons 0 1.0 License. You may use this data in any legal manner but note that information provided at any 3rd party links included in the KEV database are bound by the policies and licenses of those 3rd party websites. Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS." |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit probability per CVE | `epss_scores-current.csv.gz` | **To confirm.** Secondary copies of FIRST's EPSS usage agreement say the scores are granted freely to the public and ask for attribution to EPSS where practical; the original page at first.org could not be read from the build environment |
| [NVD API 2.0](https://nvd.nist.gov/developers) | Monthly and daily CVE counts; CVSS for unrated advisories | `/rest/json/cves/2.0` | Required notice: "This product uses the NVD API but is not endorsed or certified by the NVD." (in the page footer). Works without a key at ~1 request / 6.5 s; set `NVD_API_KEY` to go faster |
| npm downloads API, [pypistats](https://pypistats.org) | Tile size: downloads last week | `api.npmjs.org/downloads/point/last-week/…`, `pypistats.org/api/packages/…/recent` | **To confirm** |
| crates.io, Packagist, RubyGems, hex.pm APIs | Tile size: crates.io downloads in 90 days, Packagist in 30 days, RubyGems all time, Hex last week | `crates.io/api/v1/crates/…` (1 request/s, identifying User-Agent), `packagist.org/packages/….json`, `rubygems.org/api/v1/gems/….json`, `hex.pm/api/packages/…` | **To confirm** |
| Bricolage Grotesque, IBM Plex Sans | Type, self-hosted in `fonts/` (no third-party requests) | Downloaded once from Google Fonts | SIL Open Font License 1.1 (`fonts/OFL-*.txt`) |
| [Stack Overflow Developer Survey 2026](https://survey.stackoverflow.co/2026/technology/data) | Group area, framework picks and shares | Numbers copied by hand into `stacks.yml` | **To confirm** (the survey's public data is usually published under the Open Database License) |
| [deps.dev](https://deps.dev) | Not used yet (candidate for Maven / Go popularity) | — | Data it generates is CC-BY 4.0; API use is subject to the Google API Terms of Service; caching is expressly permitted (README of `google/deps.dev`, checked 2026-10-25) |

Each group uses one metric, so tile sizes compare only within a group. Maven
and Go have no public download counts, and NuGet's search API (which has them)
could not be reached from the build environment, so these three use a fixed
weight (`weight:` in `stacks.yml`, default 1). When a download API fails, the
tile falls back to the same fixed weight; the page says which sizing was used.

If a source cannot be reached, its fields are written as `null`, the failure is
recorded under `sources` in `latest.json`, and the page shows a notice instead
of a number. Monthly NVD counts from an earlier run are reused when NVD is down.

## Data files

- `data/latest.json`: everything the page draws: generation time, top numbers,
  ecosystem → package → advisories of the last 30 days (with KEV, EPSS, fixed
  versions), monthly NVD counts, and this week's KEV additions.
- `data/history/YYYY-MM-DD.json`: a copy of each day's file, for day-over-day
  changes later.

## Run locally

Python 3.10 or newer.

```sh
pip install -r collect/requirements.txt   # PyYAML only
python collect/collect.py                 # writes data/latest.json (~5 min, mostly NVD rate limits)
python -m http.server                     # then open http://localhost:8000/
```

`index.html` has no build step and no dependencies; it fetches
`data/latest.json` from the same directory.

## Daily collection

[`.github/workflows/collect.yml`](../.github/workflows/collect.yml) runs every day
at 06:17 UTC and on demand (Actions → collect → Run workflow), then commits
`data/`. Add an `NVD_API_KEY` repository secret to speed up the NVD calls
(optional).

### Social preview

`og.png` (1200x630) is the link preview image. It is rendered from
[`og/og-template.html`](../og/og-template.html) with `node og/render.js`
(Playwright). It shows ecosystem names only, never real packages, because
link previews are cached for a long time and the data changes daily. The
`og:url` and `og:image` tags in `index.html` point to depweather.com.

### Publishing

[`.github/workflows/pages.yml`](../.github/workflows/pages.yml) publishes the site
to GitHub Pages on every push to `main` and after each successful collection.
It uploads only what the page loads (`index.html`, `favicon.svg`, `og.png`,
`robots.txt`, `sitemap.xml`, `fonts/`, `data/latest.json`).

One-time setup: Settings → Pages → Source: GitHub Actions; then Custom
domain: `depweather.com` with "Enforce HTTPS". DNS at the registrar: `A`
records for `@` to 185.199.108.153, 185.199.109.153, 185.199.110.153 and
185.199.111.153, and a `CNAME` record for `www` to `surinkim.github.io`.
