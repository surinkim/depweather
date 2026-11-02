# Alerts

**English** | [한국어](alerts.ko.md) · [Back to README](../README.md)

Two ways to hear about a new advisory. Neither one needs an account on depweather, and depweather stores nothing about who is listening. There is no server and no mailing list. Email is not part of this.

## Atom feed

The site feed lists new advisories for the packages depweather tracks:

**https://depweather.com/feed.xml**

The page has `<link rel="alternate" type="application/atom+xml">`, so a feed reader that is given the homepage can find it.

One package has its own feed. The path is the package key from `data/latest.json`, with one change: a `:` in a Maven coordinate is written as `~`. A real `~` in a name is written as `~~`.

| Package | Feed |
|---|---|
| Next.js | https://depweather.com/feed/npm/next.xml |
| Django | https://depweather.com/feed/pypi/django.xml |
| Angular (`@angular/core`) | https://depweather.com/feed/npm/@angular/core.xml |
| Spring Boot | https://depweather.com/feed/maven/org.springframework.boot~spring-boot.xml |
| Gin | https://depweather.com/feed/go/github.com/gin-gonic/gin.xml |
| Symfony | https://depweather.com/feed/packagist/symfony/http-kernel.xml |

An empty feed is still valid. Subscribe before the next advisory and the reader will pick it up later.

Each item is one advisory on one package. The `<id>` is `tag:depweather.com,2026:advisory:` plus the package key and the advisory id. It does not include the time the snapshot was built, so the twice-daily rebuild does not show the same advisory again. If an old advisory is added to CISA KEV, the same id is kept and `<updated>` moves to the day it was added.

KEV items start with `KEV ·`. Critical items start with `Critical ·`. A malicious-package report starts with `Malicious ·`. Other severities are in the feed too; they are not badged. The body links to the advisory, the package on depweather, and that package's feed.

Items stay for **14 days**, counted from publication or from the KEV addition, whichever is later. The snapshot underneath only holds 30 days. The site-wide feed keeps at most 200 items; a package feed keeps every item in the window. Advisory text is English, because that is the language of the upstream data.

The files are built from `data/latest.json` when the site is published (`python collect/feeds.py`). They are not committed.

## GitHub Actions in your repository

Copy [`examples/depweather-alert.yml`](../examples/depweather-alert.yml) to `.github/workflows/depweather.yml` in **your** repository and commit it. The workflow is also a [reusable action](../alert/action.yml) (`surinkim/depweather/alert`).

Once a day (and whenever you run it by hand) it:

1. Checks out your repository and reads dependency manifests in place. The parser is [`js/stack.js`](../js/stack.js), the same one the website uses for "My stack".
2. Downloads https://depweather.com/data/latest.json.
3. When a tracked package has a new advisory at or above the severity you set, opens an issue.
4. If the `DEPWEATHER_WEBHOOK_URL` secret is set, posts the same alert to Slack or Discord.

It does not send your manifests anywhere. Matching happens on the GitHub runner.

### Setup

1. Copy the example to `.github/workflows/depweather.yml`.
2. Commit and push.
3. Optional: in the repository, Settings → Secrets and variables → Actions → New repository secret. Name it `DEPWEATHER_WEBHOOK_URL`. Paste a Slack incoming-webhook URL, or a Discord webhook URL (`https://discord.com/api/webhooks/...`).
4. Actions → depweather → Run workflow, to try it once instead of waiting for the schedule.

The workflow needs `issues: write`. The example sets that. `GITHUB_TOKEN` is passed in explicitly because a composite action does not see it otherwise.

### What counts as new

| Input | Default | Meaning |
|---|---|---|
| `severity` | `critical` | `low`, `medium`, `high`, `critical`, or `kev`. KEV always alerts, except when `severity` is `kev`, which means KEV only. A malicious-package report alerts at every level except `kev`. |
| `days` | `7` | Publication, or the KEV addition, must fall inside this many days. Values above 30 are clamped to 30, which is all the snapshot stores. |
| `open-issue` | `true` | Leave the issue open. `false` still files an issue and closes it when a webhook is set, so the webhook is not sent again tomorrow. |
| `max` | `20` | New alerts per run. The rest wait for the next run. |

### The same advisory is not opened every day

The issue body contains an HTML comment, `<!-- depweather-id:npm/next/GHSA-xxxx -->`, and the issue is labeled `depweather`. The next run lists issues with that label, open and closed, and skips ids it has already recorded.

Closing the issue does not cause a repeat. Delete the issue if you want the alert again.

With `open-issue: false` and a webhook, the closed issue is only the record. With both off, the run prints matches and records nothing, so the next run prints them again.

### Slack and Discord

A Discord URL (`discord.com/api/webhooks` or `discordapp.com`) is sent as `{"content": "..."}`. Any other URL is sent as Slack-style `{"text": "..."}`. The URL is not printed in the log.

The issue is created first, then the webhook is sent. If the webhook fails, the issue is already the dedup record, so the next run does not retry the webhook. Delete that issue and run the workflow again.

### First run

Nothing has been recorded yet, so every match inside the window is new. That can be several issues. Close the ones you already know about. At most 20 are opened per run.

### Which files are read

The same set as "My stack" on the website: `package.json` (and the root dependencies of a lockfile), `requirements.txt` and `requirements-*.txt`, `pyproject.toml`, `Pipfile`, `go.mod`, `Cargo.toml`, `pom.xml`, `Gemfile`, `composer.json`, `mix.exs`, NuGet `PackageReference` / `packages.config` / `*.csproj`.

`node_modules`, `vendor`, and other build directories are skipped. Names match inside their ecosystem only. PyPI follows PEP 503. The `match` aliases from the website apply here too, so a Spring Boot starter counts as Spring Boot, Rails components count as Rails, and Symfony packages count as Symfony.

### Limits

- Only the packages depweather tracks (about 150). Everything else is ignored, even if the manifest lists it.
- It does not check the version you have installed. The issue quotes fixed versions from the advisory; you still have to read it.
- Gradle, sbt, `pubspec.yaml`, `setup.py`, and transitive dependencies in lockfiles are not read. npm lockfiles contribute the root package's direct dependencies only.
- Runtimes and servers (PHP, nginx, Node.js) rarely appear in a language manifest, so this alert usually does not see them. Their feeds still update.
- Severity comes from the upstream advisory and can be wrong.
- The snapshot is rebuilt twice a day, so an advisory can be a few hours old before it shows up.
- The first run, and any run after the dedup issues were deleted, reports the whole window again.
- A renamed fork or a private registry name will not match.
- Webhook-only mode still needs `issues: write`, because the closed issue is what stops a repeat.
- There is no email.

## Files

- [`examples/depweather-alert.yml`](../examples/depweather-alert.yml) — the workflow to copy
- [`alert/action.yml`](../alert/action.yml) — the reusable action
- [`alert/check.js`](../alert/check.js) — matching and the severity rule, covered by `node --test tests/alert.test.js`
- [`collect/feeds.py`](../collect/feeds.py) — feed writer, covered by `python tests/test_feeds.py`
