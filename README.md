# depweather

Today's vulnerability forecast for popular packages.

depweather shows recent vulnerabilities in popular open-source packages as one
treemap, grouped by ecosystem. It is a static site: a daily GitHub Actions job
collects public data into `data/latest.json`, and a single `index.html` draws it.
There is no server, no login, no ads, and it does not scan your repositories
(that is what Dependabot, `npm audit`, `pip-audit` and `govulncheck` are for).

Status: proof of concept, private while it is being tried out.

## What it shows

**Numbers on top**

| Number | Meaning |
|---|---|
| New CVEs today | CVEs published in NVD since 00:00 UTC (rejected CVEs excluded) |
| CVEs this month | NVD CVEs published this month so far, and the change against the same month last year (whole month) |
| New in CISA KEV, 7 days | Entries added to the KEV catalog in the last 7 days, any vendor |
| Popular packages affected | Tracked packages with at least one advisory published in the last 7 days |

**A. Treemap (default view).** One group per ecosystem (npm, PyPI, Maven, Go),
each with the same area. Inside a group, tile size is the package's weekly
downloads (npm, PyPI) or a fixed weight (Maven, Go; see below). Tile color is
the worst advisory *published* in the last 7 days (toggle: 30 days). "KEV only"
keeps only advisories whose CVE is in the CISA KEV catalog.

**C. Timeline.** Click a tile or search a package: every advisory of the last
30 days is a dot on the day it was published, with the fixed versions on the
right and a table of advisories below. Default view on screens narrower than
768px.

**B. Counter (option).** Monthly NVD CVE counts for the last 14 months, a
7-day table per ecosystem (new / critical / KEV), and this week's KEV
additions. Overall CVE counts are what [cve.icu](https://cve.icu) already does
well; this view is a side panel, not the point.

The view is kept in the URL (`?view=a|b|c`, `?pkg=npm/next`, `&range=30`,
`&kev=1`) so links can be shared. The last view, period and theme are
remembered in `localStorage`.

## Colors

| Color | Meaning |
|---|---|
| Gray | No advisory in the period |
| Yellow | Low or medium, or no severity given by any source |
| Orange | High |
| Red | Critical, **or** the CVE is in CISA KEV, or a malicious-package report (OSV `MAL-`) |

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

The default list in [`collect/stacks.yml`](collect/stacks.yml) has 12 popular
packages per ecosystem. It only holds widely used packages; it should not hint
at any company's stack. Additions are welcome as pull requests. To track a
personal list without committing it, point the collector at another file:

```sh
DEPWEATHER_STACKS=~/my-stacks.yml python collect/collect.py
```

Not in the POC:

- **Infrastructure group** (OpenSSL, nginx, Kubernetes components, …). OpenSSL
  and nginx are not packages in an OSV ecosystem; covering them needs NVD CPE
  matching. Kubernetes is tracked as the Go module `k8s.io/kubernetes`.
- **Search beyond the list.** Search only finds tracked packages for now.
- **Security fixes without a CVE** (release notes), from the planning notes.

## Data sources and licenses

| Source | Used for | How | Terms |
|---|---|---|---|
| [OSV.dev](https://osv.dev) | Advisories, affected and fixed versions, aliases | Per-ecosystem export on `osv-vulnerabilities.storage.googleapis.com` (`modified_id.csv`, then one JSON per entry changed in the window) | Records keep the license of their upstream database. **To confirm**: the OSV data license page, not reachable from the environment this was written in |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Most npm / PyPI / Maven / Go advisories, via OSV | — | CC-BY 4.0 (`LICENSE.md` in the repository, checked 2026-10-25). Attribution in the page footer |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited flag, 7-day additions | `known_exploited_vulnerabilities.json`, falling back to CISA's GitHub mirror `cisagov/kev-data` | CC0 1.0. From the `cisagov/kev-data` LICENSE (checked 2026-10-25): "The KEV database is distributed under the Creative Commons 0 1.0 License. You may use this data in any legal manner but note that information provided at any 3rd party links included in the KEV database are bound by the policies and licenses of those 3rd party websites. Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS." |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit probability per CVE | `epss_scores-current.csv.gz` | **To confirm.** Secondary copies of FIRST's EPSS usage agreement say the scores are granted freely to the public and ask for attribution to EPSS where practical; the original page at first.org could not be read from the build environment |
| [NVD API 2.0](https://nvd.nist.gov/developers) | Monthly and daily CVE counts; CVSS for unrated advisories | `/rest/json/cves/2.0` | Required notice: "This product uses the NVD API but is not endorsed or certified by the NVD." (in the page footer). Works without a key at ~1 request / 6.5 s; set `NVD_API_KEY` to go faster |
| npm downloads API, [pypistats](https://pypistats.org) | Tile size (weekly downloads) | `api.npmjs.org/downloads/point/last-week/…`, `pypistats.org/api/packages/…/recent` | **To confirm** |
| [deps.dev](https://deps.dev) | Not used yet (candidate for Maven / Go popularity) | — | Data it generates is CC-BY 4.0; API use is subject to the Google API Terms of Service; caching is expressly permitted (README of `google/deps.dev`, checked 2026-10-25) |

Maven and Go have no public download counts, so their tiles use a fixed
weight (`weight:` in `stacks.yml`, default 1). When the npm or PyPI API fails,
those tiles fall back to the same fixed weight; the page says which sizing was
used.

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

[`.github/workflows/collect.yml`](.github/workflows/collect.yml) runs every day
at 06:17 UTC and on demand (Actions → collect → Run workflow), then commits
`data/`. Add an `NVD_API_KEY` repository secret to speed up the NVD calls
(optional).

### After the repository goes public

GitHub Pages is not set up yet because the repository is private. When it goes
public:

1. Settings → Pages → Source: GitHub Actions.
2. Add a deploy job to `collect.yml` after the commit step
   (`actions/configure-pages`, `actions/upload-pages-artifact` with `path: .`,
   `actions/deploy-pages`, with `pages: write` and `id-token: write`
   permissions).
3. Later: custom domain `depweather.com` (a `CNAME` file plus DNS).

## License

Code: MIT, see [LICENSE](LICENSE). Data belongs to its sources under the terms
above.
