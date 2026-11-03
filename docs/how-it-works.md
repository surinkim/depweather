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

**Package pages.** Each tracked package has a static page at
`/pkg/<ecosystem>/<name>/` (a Maven `:` is written as `~`, same as the feed).
It lists the last 7 days separately from the rest of the 30-day window, with
severity, fixed versions, CISA KEV and EPSS, and a longer trend (below).
English is the page itself; Korean is `?lang=ko`. Light and dark follow the
same control as the map.
The publish step builds these pages, and the sitemap entries for them, from
`data/latest.json` and `data/history/`. They are not committed. A tile, the package name on the
weather strip, a timeline row and a stack chip link there. Search does too.

<a id="readme-badge"></a>

**README badge.** Each tracked package has a static SVG at
`/badge/<ecosystem>/<name>.svg`. The slug is the package page's (`:` in a
Maven name is `~`, a real `~` is `~~`). Korean text is the same path with
`.ko.svg` (`/badge/npm/lodash.ko.svg`). The publish step builds both from
`data/latest.json`. They are not committed. The package page has the
Markdown and HTML to copy, in English or Korean. That panel follows the
light and dark theme. The picture does not: a README shows it as an image
on either background, so the colors stay fixed.

The badge is the last 7 days, the same window as the map and the package
page's Current section. An advisory counts when it was published in that
window, or when it was added to CISA KEV in that window if that is later.
The left side says `depweather`. The right side is the package and the status:

| Status | Color | When |
|---|---|---|
| clear / 맑음 | Gray | Nothing in the 7 days |
| cloudy / 흐림 | Yellow | Low, medium, or unknown only |
| `2 high` / `높음 2건` | Orange | That many high advisories, and nothing critical or in KEV |
| `1 critical` / `치명 1건` | Red | That many critical advisories, or a malicious-package report. A high count is added when both exist (`1 critical, 2 high`) |
| `KEV` | Magenta | At least one of those advisories is in CISA KEV. KEV is the first word and the whole right-hand color. The critical or high count still shows (`KEV · 1 critical`) |

Those are the map's severity colors. The critical red on the badge is a step
darker than the tile, so the small white word stays readable (the tile red
with white text is a little under 4.5:1 at this size). The package name is
escaped. The file links to the package page. So does the snippet. The
snippet's link is the one that works in a README, because an `<img>` does
not follow a link drawn inside the SVG.

GitHub does not request the image from depweather on every view. README
images go through GitHub's camo proxy (`camo.githubusercontent.com`), which
fetches the SVG and caches it. The badge URL does not change between
publishes, so camo can keep serving the previous file for hours after this
site has a new one. depweather cannot clear that cache. The package page is
current; a README can lag. Camo also rewrites SVG and drops scripts. The
badge is rectangles and text, and the link people click is outside the file,
so that rewrite does not change what the badge is for.

**C. Timeline.** The list names link to those pages. `?pkg=npm/next` still
opens that package's 30-day timeline on the map: dots on the day each advisory
was published, fixed versions on the right, and a table below. Default view
on screens narrower than 768px.

**B. Counter (option).** A long-term chart for one ecosystem or all tracked
packages (3M / 6M / 1Y, below), then monthly NVD CVE counts for the last 14
months, a 7-day table per ecosystem (new / critical / KEV), and this week's
KEV additions. Overall CVE counts are what [cve.icu](https://cve.icu) already
does well; this view is a side panel, not the point.

<a id="history"></a>

**Longer trend.** The package page and the Counter both draw severity-stacked
bars for a window longer than 30 days. **3M** and **6M** are the current
calendar month plus the two or five before it, one bar per week (Monday to
Sunday, clipped to the window). **1Y** is the calendar month of the day 365
days earlier through the current month, one bar per month. The last bar is
the current week or month so far.

The stack, bottom to top, is unknown, low, medium, high, critical. A magenta
diamond marks a bar that contains at least one CISA KEV advisory. KEV is not
an extra slice: those advisories are already in a severity segment, and the
number table under "Numbers for this chart" / "이 그래프의 숫자" gives the
count. The chart is inline SVG (no chart library). Colors are the page's CSS
variables, so light and dark follow the theme. Package names and every other
string taken from the data are escaped. The SVG has a text alternative, and
the table is the same numbers without the picture.

An advisory counts on the UTC day it was published, or on the day it was
added to CISA KEV if that is later (the same effective date as the 30-day
view). Several OSV records for one issue count once. On a package page the
bar is that package. On the Counter, an ecosystem bar counts an advisory once
even when it lists several tracked packages. "My stack" sums the packages in
the stack instead, so the same advisory can count once per package in the stack.

The interface is in English or Korean (EN / KO at the top right; the first
visit follows the browser language). Advisory text from the data stays in
English.

The view is kept in the URL (`?view=a|b|c`, `?pkg=npm/next`, `&range=30`,
`&kev=1`, `&lang=ko`, `&stack=`) so links can be shared. The last view, period, language
and theme are remembered in `localStorage`. The footer shows the page version,
which helps spot a stale copy in the browser cache (reload with Cmd/Ctrl +
Shift + R).

**My stack.** "My stack" filters the forecast, the map, the timeline and the
per-ecosystem counts to packages named in a manifest you paste. Supported
files: npm `package.json` (and the direct dependencies of a package-lock),
PyPI `requirements.txt`, `pyproject.toml` and `Pipfile`, `go.mod`,
`Cargo.toml`, Maven `pom.xml`, `Gemfile`, `composer.json`, Elixir `mix.exs`,
and NuGet `PackageReference` / `packages.config`. Names are matched inside
that ecosystem, including PyPI normalization (case, `_`, `.`, `-`) and the
same `match` aliases as [`collect/stacks.yml`](../collect/stacks.yml) (a
Spring Boot starter counts as Spring Boot, a Rails component counts as
Rails). Packages this site does not track are listed under "Not tracked by
depweather" and are not put in the link. The choice is stored in
`localStorage` (`depweather:stack`). The `stack` query parameter is the
tracked package keys joined with commas (`npm/react,pypi/django`), or `-`
when none of them are tracked. Nothing is uploaded.

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

An older advisory counts as new on the day its CVE is added to CISA KEV:
"recent" means published, or added to KEV, within the period. The daily run
looks these up per package through the OSV query API, since an old bug that
starts being exploited is exactly what this page should not miss.

Affected tiles carry the glyph, and timeline dots change shape with severity
(circle, triangle, diamond), so severity never depends on color alone.

Severity is taken in this order: the label the advisory database put on the
record (GitHub Advisory, Bitnami and others) → a CVSS v3 score computed from the
OSV vector → the NVD CVSS base severity (for advisories still unrated, e.g. Go
standard library entries) → "unknown" (shown yellow). When OSV lists the same
issue under several IDs (`GO-`, `PYSEC-`, `GHSA-`), they are merged and the
highest severity wins.

The CVSS number comes from the advisory's own vector when it has one, otherwise
from NVD, which is asked even when the advisory already has a label. A rated
advisory keeps its own label; NVD only adds the number. NVD answers are cached
in `data/nvd_cvss.json`, and CVEs NVD has not scored yet are asked again once a
day. The tooltip and table say where the label and the number came from.

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
| [NVD API 2.0](https://nvd.nist.gov/developers) | Monthly and daily CVE counts; CVSS for advisories without a score | `/rest/json/cves/2.0` | Required notice: "This product uses the NVD API but is not endorsed or certified by the NVD." (in the page footer). Works without a key at ~1 request / 6.5 s; set `NVD_API_KEY` to go faster |
| npm downloads API, [pypistats](https://pypistats.org) | Tile size: downloads last week | `api.npmjs.org/downloads/point/last-week/…`, `pypistats.org/api/packages/…/recent` | **To confirm** |
| crates.io, Packagist, RubyGems, hex.pm APIs | Tile size: crates.io downloads in 90 days, Packagist in 30 days, RubyGems all time, Hex last week | `crates.io/api/v1/crates/…` (1 request/s, identifying User-Agent), `packagist.org/packages/….json`, `rubygems.org/api/v1/gems/….json`, `hex.pm/api/packages/…` | **To confirm** |
| Bricolage Grotesque, IBM Plex Sans | Type, self-hosted in `fonts/` (no request to Google Fonts) | Downloaded once from Google Fonts | SIL Open Font License 1.1 (`fonts/OFL-*.txt`) |
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
- `data/today.md` (published as `/today.md`): the day's forecast in plain
  Markdown, for search engines, AI assistants and anyone without JavaScript.
- `llms.txt` (published as `/llms.txt`): a short guide to the site and its data
  files for AI assistants ([llmstxt.org](https://llmstxt.org)).
- `data/history/YYYY-MM.json`: compact daily counts for that month, committed
  with the rest of `data/`. A day lists only packages and ecosystems that had
  an advisory. Keys are `c` critical, `h` high, `m` medium, `l` low, `u`
  unknown, and `k` for how many of those are in CISA KEV. Zero counts are
  omitted. `data/history/manifest.json` lists the months so the Counter view
  can fetch them. These files are not gitignored. Older runs wrote a full
  copy of `latest.json` to `data/history/YYYY-MM-DD.json`; the collector
  deletes those leftovers and does not write new ones. A month stays in the
  tens of kilobytes, so it rides along in the existing twice-a-day `data/`
  commit on `main` instead of a separate data branch (Pages deploys `main`,
  and a second branch would not show up on the site unless something merged
  it). The backfill below fills roughly the past year; after that the daily
  job rewrites the days its 30-day window fully covers and leaves older days
  in place.
- `feed.xml` and `feed/<package>.xml`, published as `/feed.xml` and
  `/feed/...`: Atom feeds of advisories from the last 14 days. The publish
  step builds them from `data/latest.json`; they are not committed. An item id
  is the package plus the advisory id, so a rebuild does not look like a new
  item. KEV and critical items are marked at the start of the title. See
  [alerts](alerts.md).
- `pkg/<ecosystem>/<name>/index.html`, published as `/pkg/.../`: one page per
  tracked package. Built by `collect/pages.py` in the same publish step, not
  committed. The published `sitemap.xml` adds each page in English and Korean.
- `badge/<ecosystem>/<name>.svg` and `.ko.svg`, published as `/badge/...`:
  one README badge per tracked package, for the last 7 days. Built by
  `collect/badges.py` in the same publish step, not committed.

## Run locally

Python 3.10 or newer.

```sh
pip install -r collect/requirements.txt   # PyYAML only
python collect/collect.py                 # writes data/latest.json (~5 min, mostly NVD rate limits)
python collect/feeds.py                   # writes feed.xml and feed/ from data/latest.json
python collect/pages.py                   # writes pkg/ from data/latest.json (gitignored)
python collect/badges.py                  # writes badge/ from data/latest.json (gitignored)
python collect/backfill_history.py        # one-off: fill data/history for about a year
python -m http.server                     # then open http://localhost:8000/
```

`backfill_history.py` is not part of the daily job or the Pages build. It
downloads the CISA KEV catalog once and one OSV `all.zip` per ecosystem
(about 315 MB; npm is most of that), sequentially, with a pause between
requests, a `depweather-backfill` User-Agent, and `Retry-After` backoff on
429 and 503. Zips are cached in `.cache/osv/` (gitignored), so a second run
makes no HTTP requests. It does not call NVD and does not request individual
advisories. Severity comes from the advisory label or a CVSS v3 vector in
the OSV record.

`index.html` has no build step and no dependencies; it fetches
`data/latest.json` from the same directory.

## Daily collection

[`.github/workflows/collect.yml`](../.github/workflows/collect.yml) runs twice a
day, at 06:17 and 18:17 UTC (GitHub can delay or skip a scheduled run), and on demand (Actions → collect → Run workflow), then commits
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
`robots.txt`, `sitemap.xml`, `fonts/`, `js/stack.js`, `data/latest.json`), the
plain-text views (`llms.txt`, `today.md`), Atom feeds built by
`python collect/feeds.py` (`feed.xml`, `feed/`), package pages built by
`python collect/pages.py` (`pkg/`, plus package URLs in the published sitemap),
and README badges built by `python collect/badges.py` (`badge/`).

One-time setup: Settings → Pages → Source: GitHub Actions; then Custom
domain: `depweather.com` with "Enforce HTTPS". DNS at the registrar: `A`
records for `@` to 185.199.108.153, 185.199.109.153, 185.199.110.153 and
185.199.111.153, and a `CNAME` record for `www` to `surinkim.github.io`.
