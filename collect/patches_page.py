#!/usr/bin/env python3
"""Write the runtime patch status page from data/patches.json.

    <out>/patches/index.html      English  (https://depweather.com/patches/)
    <out>/ko/patches/index.html   Korean   (https://depweather.com/ko/patches/)

The whole tree (language, major version, distribution, details) is rendered
here, so the page reads without JavaScript. js/patches.js only opens and
closes rows, filters them (search box, "my stack only") and remembers the
choice in this browser. Nothing is sent anywhere. Times are stored in UTC and
shown in KST. Only what data/patches.json says is shown: a CVE id that is not
a real CVE id, or has no score of 7.0 or more, is never rendered.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collect"))

import feeds  # noqa: E402
import pages  # noqa: E402  (shared head code, link allowlist, CVE id pattern)

SITE = feeds.SITE
LANGS = ("en", "ko")
KST = timezone(timedelta(hours=9))
EOL_SOON_DAYS = 180
HIGH_CVSS = 7.0
FONTS_JS = "/js/patches.js?v=2026-11-22.1"
SOURCES_LINE = [
    ("endoflife.date", "https://endoflife.date"),
    ("OSV", "https://osv.dev"),
    ("GitHub Releases", "https://github.com"),
    ("Docker Hub", "https://hub.docker.com"),
    ("NVD", "https://nvd.nist.gov"),
]

S = {
    "en": {
        "title": "Runtime patches: latest releases and official image status — depweather",
        "desc": ("The latest patch of the runtimes you use, whether the official container image has it, "
                 "and what to do if not. Java, Go, Node.js and Python, updated twice a day."),
        "h1": "Runtime patches",
        "lede": "The latest patch of the runtimes you use, whether the official image has it yet, and what to do if not.",
        "updated": "Last updated",
        "home": "Vulnerability map",
        "nav": "Patches",
        "theme": "Theme",
        "card_new": "New patches, last 7 days",
        "card_pending": "Images waiting for a patch",
        "card_cve": "High-severity CVEs fixed",
        "unit": "",
        "search": "Search language, version, distribution (e.g. Java 17, Corretto)",
        "mine": "My stack only",
        "mine_hint": "Star rows to build your stack. It is saved in this browser only.",
        "star": "Add to my stack",
        "col_name": "Version / distribution",
        "col_patch": "Latest patch",
        "col_time": "Released (KST)",
        "col_hub": "Docker Hub",
        "col_ecr": "Public ECR",
        "col_eol": "End of support",
        "col_cve": "High CVEs",
        "ecr_soon": "Public ECR is not collected yet",
        "supported": "supported versions {n}",
        "waiting": "waiting {k}",
        "cves": "high CVEs {n}",
        "dists": "{n} distributions",
        "date_only": "date only (no time of day from the source)",
        "pending": "waiting {h}",
        "reflected": "in image",
        "unknown": "unknown",
        "lts": "LTS",
        "eol_badge": "ended",
        "ended_tag": "Ended",
        "left": "{n} days left",
        "none": "none",
        "cve_h": "High-severity CVEs fixed in this patch",
        "cve_none": "None found in the sources below.",
        "cve_unknown": "Not covered: no matching OSV source for this product.",
        "cve_fixed": "fixed in {v}",
        "cve_unrated": "{n} CVE(s) fixed here have no CVSS score yet and are not counted.",
        "cve_sources": "Sources",
        "img_h": "Official image tags · build time",
        "img_tag": "Tag",
        "img_reg": "Registry",
        "img_built": "Last push (KST)",
        "img_state": "Holds the patch",
        "yes": "yes",
        "no": "no",
        "missing": "not published",
        "img_note_exact": "A tag named after the full patch decides. Other tags count only with the same digest.",
        "img_note_after": "No tag names the full patch; a tag counts when it was pushed after the patch.",
        "rebuilt": "built long after the release; Docker Hub shows only the last push, so no delay is claimed",
        "work_h": "If you must patch right now",
        "work_note": "The official image does not have the patch yet. Check the checksum against the vendor's official page before use.",
        "log_h": "Recent changes",
        "log_empty": "No changes recorded yet.",
        "eol_h": "Ending support soon",
        "eol_empty": "Nothing ends within 6 months.",
        "sources": "Sources",
        "footer_nvd": "This product uses the NVD API but is not endorsed or certified by the NVD.",
        "footer_cve": "CVE counts cover only advisories found in the listed OSV sources; 0 means none found there, not that none exist.",
        "footer_time": "The Docker Hub time is the last push of a tag; official images are rebuilt, so a delay is shown only when the push came within a week of the patch.",
        "footer_analytics": "This site uses Google Analytics to count visits.",
        "empty_search": "Nothing matches.",
        "no_data": "No data yet.",
    },
    "ko": {
        "title": "런타임 패치 현황: 최신 패치와 공식 이미지 반영 여부 — depweather",
        "desc": ("자주 쓰는 런타임의 최신 패치, 공식 컨테이너 이미지 반영 여부, 아직이면 대응법을 한 화면에. "
                 "Java, Go, Node.js, Python을 하루 두 번 갱신합니다."),
        "h1": "런타임 패치 현황",
        "lede": "자주 쓰는 런타임의 최신 패치, 공식 이미지 반영 여부, 아직이면 대응법을 한 화면에.",
        "updated": "마지막 갱신",
        "home": "취약점 지도",
        "nav": "패치",
        "theme": "테마",
        "card_new": "최근 7일 새 패치",
        "card_pending": "이미지 반영 대기",
        "card_cve": "수정된 고위험 CVE",
        "unit": "건",
        "search": "언어 · 버전 · 배포판 검색 (예: Java 17, Corretto)",
        "mine": "내 스택만 보기",
        "mine_hint": "행의 별표로 내 스택을 만듭니다. 이 브라우저에만 저장됩니다.",
        "star": "내 스택에 추가",
        "col_name": "버전 / 배포판",
        "col_patch": "최신 패치",
        "col_time": "나온 시각 (KST)",
        "col_hub": "Docker Hub",
        "col_ecr": "Public ECR",
        "col_eol": "지원 종료",
        "col_cve": "고위험 CVE",
        "ecr_soon": "Public ECR은 아직 수집하지 않습니다",
        "supported": "지원 중 버전 {n}개",
        "waiting": "대기 {k}",
        "cves": "고위험 CVE {n}",
        "dists": "배포판 {n}개",
        "date_only": "날짜만 있음 (출처가 시각을 주지 않음)",
        "pending": "대기 {h}",
        "reflected": "이미지에 반영",
        "unknown": "확인 불가",
        "lts": "LTS",
        "eol_badge": "종료",
        "ended_tag": "종료됨",
        "left": "{n}일 남음",
        "none": "없음",
        "cve_h": "이 패치에서 수정된 고위험 CVE",
        "cve_none": "아래 출처에서는 찾지 못했습니다.",
        "cve_unknown": "확인 불가: 이 제품에 맞는 OSV 출처가 없습니다.",
        "cve_fixed": "{v}에서 수정",
        "cve_unrated": "이 패치에서 수정된 CVE 중 {n}건은 아직 CVSS 점수가 없어 세지 않았습니다.",
        "cve_sources": "출처",
        "img_h": "공식 이미지 태그 · 빌드 시각",
        "img_tag": "태그",
        "img_reg": "레지스트리",
        "img_built": "마지막 푸시 (KST)",
        "img_state": "패치 포함",
        "yes": "예",
        "no": "아니오",
        "missing": "아직 없음",
        "img_note_exact": "패치 전체 버전이 이름에 든 태그가 기준입니다. 다른 태그는 같은 digest일 때만 인정합니다.",
        "img_note_after": "패치 버전을 이름에 담은 태그가 없어, 패치 이후에 푸시된 태그를 반영으로 봅니다.",
        "rebuilt": "릴리스 한참 뒤에 빌드됨. Docker Hub는 마지막 푸시만 알려 주므로 지연 시간을 표시하지 않습니다",
        "work_h": "지금 당장 패치해야 하면",
        "work_note": "공식 이미지에 아직 패치가 없습니다. 사용 전에 벤더 공식 페이지에서 체크섬을 확인하세요.",
        "log_h": "최근 변경",
        "log_empty": "아직 기록된 변경이 없습니다.",
        "eol_h": "곧 지원 종료",
        "eol_empty": "6개월 안에 끝나는 지원이 없습니다.",
        "sources": "출처",
        "footer_nvd": "이 제품은 NVD API를 사용하지만 NVD가 보증하거나 인증하지 않습니다.",
        "footer_cve": "CVE 건수는 나열한 OSV 출처에서 찾은 권고만 셉니다. 0건은 그곳에서 찾지 못했다는 뜻이며 없다는 보증이 아닙니다.",
        "footer_time": "Docker Hub 시각은 태그의 마지막 푸시입니다. 공식 이미지는 다시 빌드되므로 지연 시간은 패치 후 일주일 안에 푸시된 경우에만 표시합니다.",
        "footer_analytics": "방문 통계를 위해 Google Analytics를 사용합니다.",
        "empty_search": "일치하는 항목이 없습니다.",
        "no_data": "아직 데이터가 없습니다.",
    },
}

LANG_COLOR = {"java": "#e76f00", "go": "#00a7d0", "nodejs": "#3c873a", "python": "#3776ab"}
LANG_ABBR = {"java": "Ja", "go": "Go", "nodejs": "N", "python": "Py"}
ALLOWED = pages.ALLOWED_LINK_HOSTS | {"hub.docker.com"}

esc = pages.esc


def parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def kst_stamp(s: str | None, date_only: bool = False) -> str:
    """'2026-11-17T20:05:00Z' -> '11/18 05:05' (KST)."""
    if not s:
        return ""
    k = parse_dt(s).astimezone(KST)
    return k.strftime("%m/%d") if date_only else k.strftime("%m/%d %H:%M")


def kst_full(s: str) -> str:
    return parse_dt(s).astimezone(KST).strftime("%m/%d %H:%M KST")


def span(hours: int) -> str:
    return f"{hours}h" if hours < 100 else f"{round(hours / 24)}d"


def eol_state(d: dict, today: date) -> str:
    if d.get("is_eol"):
        return "ended"
    if not d.get("eol_from"):
        return "none"
    days = (date.fromisoformat(d["eol_from"]) - today).days
    return "ended" if days < 0 else "soon" if days <= EOL_SOON_DAYS else "ok"


def eol_cell(eol_from: str | None, state: str, t: dict) -> str:
    if not eol_from:
        return '<span class="muted">–</span>'
    ym = eol_from[:7]
    if state == "ended":
        return f'<span class="pill bad" title="{esc(eol_from)}">{esc(ym)} {esc(t["eol_badge"])}</span>'
    if state == "soon":
        return f'<span class="pill warn" title="{esc(eol_from)}">{esc(ym)}</span>'
    return f'<span class="pill plain" title="{esc(eol_from)}">{esc(ym)}</span>'


def live_status(d: dict, now: datetime) -> dict:
    """image_status with the wait of a pending image counted up to ``now``:
    the data file is not rewritten every hour, the page build is."""
    st = dict(d.get("image_status") or {"state": "unknown"})
    if st.get("state") == "pending" and d.get("released_at"):
        st["hours"] = max(0, int((now - parse_dt(d["released_at"])).total_seconds() // 3600))
    return st


def status_cell(st: dict | None, t: dict, note: str | None = None) -> str:
    st = st or {"state": "unknown"}
    tilde = "≈" if st.get("approx") else ""
    title = f' title="{esc(t["date_only"])}"' if st.get("approx") else ""
    if st["state"] == "reflected":
        if st.get("hours") is not None:
            return f'<span class="pill ok"{title}>✅ {tilde}+{span(st["hours"])}</span>'
        tip = t["rebuilt"] if st.get("rebuilt") else t["reflected"]
        return f'<span class="pill ok" title="{esc(tip)}">✅</span>'
    if st["state"] == "pending":
        txt = t["pending"].format(h=tilde + span(st["hours"] or 0))
        return f'<span class="pill pend"{title}>⏳ {esc(txt)}</span>'
    tip = f' title="{esc(note)}"' if note else ""
    return f'<span class="pill dim"{tip}>–</span>'


def valid_cves(d: dict) -> list[dict] | None:
    """The CVEs the page may show: real ids with a score of 7.0 or more."""
    if d.get("high_cves") is None:
        return None
    out = []
    for c in d["high_cves"]:
        cvss = c.get("cvss")
        if (pages.CVE_RE.match(str(c.get("id", ""))) and isinstance(cvss, (int, float))
                and not isinstance(cvss, bool) and cvss >= HIGH_CVSS):
            out.append(c)
    return out


def cve_cell(cves: list[dict] | None, t: dict) -> str:
    if cves is None:
        return f'<span class="muted" title="{esc(t["cve_unknown"])}">–</span>'
    if not cves:
        return '<span class="muted">0</span>'
    return f'<span class="cvecount">{len(cves)}{esc(t["unit"])}</span>'


def lang_text(l: dict) -> str:
    return l["label"]


def row_attrs(key: str, parent: str, level: str, text: str, hidden: bool, extra: str = "") -> str:
    h = " hidden" if hidden else ""
    return (f'<tr class="row {level}" data-key="{esc(key)}" data-parent="{esc(parent)}" '
            f'data-search="{esc(text.lower())}"{h}{extra}>')


def star(key: str, t: dict) -> str:
    return (f'<button type="button" class="star" data-star="{esc(key)}" aria-pressed="false" '
            f'title="{esc(t["star"])}" aria-label="{esc(t["star"])}">☆</button>')


def twisty(key: str, label_html: str, expandable: bool) -> str:
    if not expandable:
        return f'<span class="twisty-gap"></span>{label_html}'
    return (f'<button type="button" class="twisty" data-toggle="{esc(key)}" aria-expanded="false">'
            f'<span class="chev" aria-hidden="true"></span>{label_html}</button>')


def detail_row(key: str, parent: str, lang: str, d: dict, t: dict) -> str:
    cves = valid_cves(d)
    if cves is None:
        cve_body = f'<p class="muted">{esc(t["cve_unknown"])}</p>'
    elif not cves:
        cve_body = f'<p class="muted">{esc(t["cve_none"])}</p>'
    else:
        items = []
        for c in cves:
            href = pages.safe_href(c.get("url"))
            idtxt = esc(c["id"])
            link = f'<a href="{esc(href)}" rel="noopener">{idtxt}</a>' if href else idtxt
            fixed = t["cve_fixed"].format(v=esc(c.get("fixed_in") or d.get("latest_patch") or ""))
            items.append(f'<li>{link} <span class="pill bad small">CVSS {c["cvss"]:.1f}</span> '
                         f'<span class="muted">· {fixed}</span></li>')
        cve_body = '<ul class="cvelist">' + "".join(items) + "</ul>"
    if cves is not None and d.get("cvss_unrated"):
        cve_body += f'<p class="muted small">{esc(t["cve_unrated"].format(n=d["cvss_unrated"]))}</p>'
    if d.get("cve_sources"):
        cve_body += (f'<p class="muted small">{esc(t["cve_sources"])}: '
                     f'{esc(", ".join(d["cve_sources"]))}</p>')

    imgs = d.get("images") or []
    if imgs:
        rows = []
        for i in imgs:
            if i.get("exists") is None:
                continue
            if not i["exists"]:
                if not i.get("exact"):
                    continue
                built, state = f'<span class="muted">{esc(t["missing"])}</span>', f'<span class="pill pend">{esc(t["no"])}</span>'
            else:
                built = esc(kst_stamp(i.get("built_at")))
                ok = i.get("contains_latest")
                state = (f'<span class="pill ok">{esc(t["yes"])}</span>' if ok
                         else f'<span class="pill pend">{esc(t["no"])}</span>')
            rows.append(f'<tr><td class="mono">{esc(i["tag"])}</td><td>Docker Hub</td>'
                        f'<td class="mono">{built}</td><td>{state}</td></tr>')
        exact = any(i.get("exact") for i in imgs)
        note = t["img_note_exact"] if exact else t["img_note_after"]
        repo = esc(imgs[0].get("repo", ""))
        img_body = (f'<div class="scroll-x"><table class="mini"><thead><tr><th>{esc(t["img_tag"])}</th>'
                    f'<th>{esc(t["img_reg"])}</th><th>{esc(t["img_built"])}</th><th>{esc(t["img_state"])}</th></tr></thead>'
                    f'<tbody>{"".join(rows)}</tbody></table></div>'
                    f'<p class="muted small"><span class="mono">{repo}</span> · {esc(note)}</p>')
    else:
        note = (d.get("image_note") or {}).get(lang) or t["unknown"]
        img_body = f'<p class="muted">{esc(note)}</p>'

    work = ""
    wd = d.get("workaround_dockerfile")
    if wd and (d.get("image_status") or {}).get("state") == "pending":
        text = wd if isinstance(wd, str) else str(wd.get("text", ""))
        work = (f'<section class="work"><h4>{esc(t["work_h"])}</h4><p class="muted small">{esc(t["work_note"])}</p>'
                f'<pre><code>{esc(text)}</code></pre></section>')

    link = ""
    href = pages.safe_href(d.get("release_url"))
    if href:
        link = f' <a class="small" href="{esc(href)}" rel="noopener">↗</a>'
    return (f'<tr class="row detail" data-key="{esc(key)}/~" data-parent="{esc(key)}" hidden><td colspan="7">'
            f'<div class="dgrid"><section class="card"><h4>{esc(t["cve_h"])}{link}</h4>{cve_body}</section>'
            f'<section class="card"><h4>{esc(t["img_h"])}</h4>{img_body}</section></div>{work}</td></tr>')


def dist_cells(d: dict, t: dict, lang: str, today: date, now: datetime) -> str:
    est = eol_state(d, today)
    date_only = d.get("released_precision") == "date"
    stamp = esc(kst_stamp(d.get("released_at"), date_only))
    time_title = f' title="{esc(t["date_only"])}"' if date_only else ""
    cves = valid_cves(d)
    note = (d.get("image_note") or {}).get(lang)
    return (f'<td class="mono">{esc(d.get("latest_patch") or "–")}</td>'
            f'<td class="mono"{time_title}>{stamp or "–"}</td>'
            f'<td>{status_cell(live_status(d, now), t, note)}</td>'
            f'<td><span class="pill dim" title="{esc(t["ecr_soon"])}">–</span></td>'
            f'<td>{eol_cell(d.get("eol_from"), est, t)}</td>'
            f'<td class="num">{cve_cell(cves, t)}</td>')


def render_rows(data: dict, lang: str, today: date, now: datetime) -> str:
    t = S[lang]
    out = []
    for l in data.get("languages") or []:
        if not l.get("versions"):
            continue
        lid = l["id"]
        all_d = [(v, d) for v in l["versions"] for d in v["distros"]]
        waiting = sum(1 for _, d in all_d if (d.get("image_status") or {}).get("state") == "pending" and not d.get("is_eol"))
        cve_ids = {c["id"] for _, d in all_d for c in (valid_cves(d) or [])}
        bits = [t["supported"].format(n=sum(1 for v in l["versions"] if not v.get("is_eol")))]
        if waiting:
            bits.append(f'<span class="pendtxt">{esc(t["waiting"].format(k=waiting))}</span>')
        if cve_ids:
            bits.append(f'<span class="badtxt">{esc(t["cves"].format(n=len(cve_ids)))}</span>')
        mark = (f'<span class="lmark" style="background:{LANG_COLOR.get(lid, "#62798d")}" aria-hidden="true">'
                f'{esc(LANG_ABBR.get(lid, l["label"][:2]))}</span>')
        out.append(row_attrs(lid, "", "lang", lang_text(l), False, ' data-open="1"'))
        out.append(f'<th scope="row" class="name">{twisty(lid, mark + "<b>" + esc(l["label"]) + "</b>", True)}</th>'
                   f'<td colspan="6" class="lsum">{" · ".join(bits)}</td></tr>')
        for v in l["versions"]:
            vkey = f"{lid}/{v['name']}"
            vname = f"{l['label']} {v['name']}"
            badges = ""
            if v.get("is_lts"):
                badges += f' <span class="pill lts">{esc(t["lts"])}</span>'
            if v.get("is_eol"):
                badges += f' <span class="pill bad small">{esc(t["eol_badge"])}</span>'
            inline = bool(v.get("inline"))
            label = f'<span class="vname">{esc(vname)}</span>{badges}'
            if inline:
                d = v["distros"][0]
                out.append(row_attrs(vkey, lid, "ver", vname, False, ' data-leaf="1"'))
                out.append(f'<th scope="row" class="name lvl1">{star(vkey, t)}{twisty(vkey, label, True)}</th>'
                           f'{dist_cells(d, t, lang, today, now)}</tr>')
                out.append(detail_row(vkey, vkey, lang, d, t))
                continue
            v_cves = {c["id"] for d in v["distros"] for c in (valid_cves(d) or [])}
            known = any(valid_cves(d) is not None for d in v["distros"])
            pend = sum(1 for d in v["distros"] if (d.get("image_status") or {}).get("state") == "pending" and not d.get("is_eol"))
            hub = esc(t["dists"].format(n=len(v["distros"])))
            if pend:
                hub += f' · <span class="pendtxt">{esc(t["waiting"].format(k=pend))}</span>'
            vcve = (f'<span class="cvecount">{len(v_cves)}{esc(t["unit"])}</span>' if v_cves
                    else '<span class="muted">0</span>' if known else '<span class="muted">–</span>')
            out.append(row_attrs(vkey, lid, "ver", vname, False))
            out.append(f'<th scope="row" class="name lvl1">{twisty(vkey, label, True)}</th>'
                       f'<td class="muted">–</td><td class="muted">–</td><td class="muted">{hub}</td><td></td>'
                       f'<td>{eol_cell(v.get("eol_from"), eol_state({"is_eol": v.get("is_eol"), "eol_from": v.get("eol_from")}, today), t)}</td>'
                       f'<td class="num">{vcve}</td></tr>')
            for d in v["distros"]:
                dkey = f"{vkey}/{d['id']}"
                text = f"{vname} {d['label']}"
                out.append(row_attrs(dkey, vkey, "dist", text, True, ' data-leaf="1"'))
                out.append(f'<th scope="row" class="name lvl2">{star(dkey, t)}'
                           f'{twisty(dkey, "<span class=vname>" + esc(d["label"]) + "</span>", True)}</th>'
                           f'{dist_cells(d, t, lang, today, now)}</tr>')
                out.append(detail_row(dkey, dkey, lang, d, t))
    return "\n".join(out)


def eol_list(data: dict, today: date) -> list[tuple[str, str, str]]:
    """(label, eol date, state) for versions ending within EOL_SOON_DAYS or
    ended within the last year, soonest first."""
    items = []
    for l in data.get("languages") or []:
        for v in l.get("versions") or []:
            for d in v["distros"]:
                if not d.get("eol_from"):
                    continue
                days = (date.fromisoformat(d["eol_from"]) - today).days
                state = eol_state(d, today)
                if state == "ended" and days >= -365 or state == "soon":
                    name = f"{l['label']} {v['name']}" if v.get("inline") else f"{l['label']} {v['name']} · {d['label']}"
                    items.append((days, name, d["eol_from"], state))
    items.sort()
    return [(n, e, s) for _, n, e, s in items[:8]]


def render_page(data: dict, lang: str, today: date | None = None, now: datetime | None = None) -> str:
    if lang not in LANGS:
        raise ValueError(f"bad page language: {lang!r}")
    t = S[lang]
    other = "en" if lang == "ko" else "ko"
    gen = parse_dt(data["generated_at"])
    now = now or gen
    today = today or now.date()
    en_url, ko_url = f"{SITE}/patches/", f"{SITE}/ko/patches/"
    page_url = ko_url if lang == "ko" else en_url
    summ = data.get("summary") or {}
    log = []
    for e in (data.get("changelog") or [])[:8]:
        log.append(f'<li><time class="mono muted">{esc(kst_stamp(e["at"]))}</time>'
                   f'<span>{esc(e.get("text_" + lang) or e.get("text_en") or "")}</span></li>')
    log_html = f'<ul class="loglist">{"".join(log)}</ul>' if log else f'<p class="muted">{esc(t["log_empty"])}</p>'
    eols = []
    for name, eol, state in eol_list(data, today):
        if state == "ended":
            tag = f'<span class="pill bad small">{esc(t["ended_tag"])}</span>'
        else:
            n = (date.fromisoformat(eol) - today).days
            tag = f'<span class="pill warn small">{esc(t["left"].format(n=n))}</span>'
        eols.append(f'<li><span><b>{esc(name)}</b> <span class="muted mono">{esc(eol)}</span></span>{tag}</li>')
    eol_html = f'<ul class="eollist">{"".join(eols)}</ul>' if eols else f'<p class="muted">{esc(t["eol_empty"])}</p>'
    rows = render_rows(data, lang, today, now) if data.get("languages") else ""
    body_rows = rows or f'<tr><td colspan="7" class="muted">{esc(t["no_data"])}</td></tr>'
    src = " · ".join(f'<a href="{u}" rel="noopener">{esc(n)}</a>' for n, u in SOURCES_LINE)
    css = _CSS
    cards = (
        f'<div class="card3"><div><span class="lab">{esc(t["card_new"])}</span><span class="num">{summ.get("new_patches_7d", 0)}<small>{esc(t["unit"])}</small></span></div><span class="ico ok">✓</span></div>'
        f'<div class="card3 amber"><div><span class="lab">{esc(t["card_pending"])}</span><span class="num">{summ.get("images_pending", 0)}<small>{esc(t["unit"])}</small></span></div><span class="ico pend">⏳</span></div>'
        f'<div class="card3 red"><div><span class="lab">{esc(t["card_cve"])}</span><span class="num">{summ.get("high_cves", 0)}<small>{esc(t["unit"])}</small></span></div><span class="ico bad">!</span></div>'
    )
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script>
{pages.LANG_REDIRECT_JS}
</script>
<script>document.documentElement.classList.add("js");</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-HF5GM88Y3V"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){{dataLayer.push(arguments);}}
  gtag('js', new Date());
  gtag('config', 'G-HF5GM88Y3V');
</script>
<title>{esc(t["title"])}</title>
<meta name="description" content="{esc(t["desc"])}">
<link rel="canonical" href="{esc(page_url)}">
{pages.hreflang_links(en_url, ko_url)}
<meta name="robots" content="index,follow">
<meta property="og:type" content="website">
<meta property="og:site_name" content="depweather">
<meta property="og:title" content="{esc(t["title"])}">
<meta property="og:description" content="{esc(t["desc"])}">
<meta property="og:url" content="{esc(page_url)}">
<meta property="og:image" content="{SITE}/og.png">
<meta property="og:locale" content="{pages.OG_LOCALE[lang]}">
<meta property="og:locale:alternate" content="{pages.OG_LOCALE[other]}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{pages.FONTS_CSS}">
<script>
try {{
  var p = JSON.parse(localStorage.getItem("depweather:prefs") || "{{}}");
  if (p.theme === "dark" || p.theme === "light") document.documentElement.dataset.theme = p.theme;
}} catch (e) {{}}
</script>
<noscript><style>tr[hidden] {{ display: table-row; }}</style></noscript>
<style>
{css}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1><a href="{pages.home_path(lang)}" id="brand"><img src="/favicon.svg" alt="depweather" width="32" height="32"><span aria-hidden="true">depweather</span></a></h1>
    <span class="spacer"></span>
    <div class="controls">
      <a class="iconbtn" href="{pages.home_path(lang)}">{esc(t["home"])}</a>
      <a class="iconbtn current" href="{'/ko/patches/' if lang == 'ko' else '/patches/'}" aria-current="page">{esc(t["nav"])}</a>
      <button type="button" class="iconbtn" id="theme">{esc(t["theme"])}</button>
      {pages.lang_switch(lang, "/patches/", "/ko/patches/", "언어" if lang == "ko" else "Language")}
      <a class="iconbtn gh" href="https://github.com/surinkim/depweather" aria-label="GitHub">GitHub</a>
    </div>
  </header>
  <main>
    <h1 class="pg">{esc(t["h1"])}</h1>
    <p class="lede">{esc(t["lede"])}</p>
    <p class="meta">{esc(t["updated"])} <b>{esc(kst_full(data["generated_at"]))}</b></p>
    <div class="cards">{cards}</div>
    <div class="tools">
      <input type="search" id="q" placeholder="{esc(t["search"])}" aria-label="{esc(t["search"])}" autocomplete="off">
      <label class="mine" title="{esc(t["mine_hint"])}"><input type="checkbox" id="mine"> {esc(t["mine"])}</label>
    </div>
    <div class="tablebox scroll-x">
    <table class="tree" id="tree" data-empty="{esc(t["empty_search"])}">
      <thead><tr><th>{esc(t["col_name"])}</th><th>{esc(t["col_patch"])}</th><th>{esc(t["col_time"])}</th><th>{esc(t["col_hub"])}</th><th>{esc(t["col_ecr"])}</th><th>{esc(t["col_eol"])}</th><th class="num">{esc(t["col_cve"])}</th></tr></thead>
      <tbody>
{body_rows}
      </tbody>
    </table>
    </div>
    <p class="note" id="nomatch" hidden>{esc(t["empty_search"])}</p>
    <div class="bottom">
      <section class="panel"><h2>{esc(t["log_h"])}</h2>{log_html}</section>
      <section class="panel"><h2>{esc(t["eol_h"])}</h2>{eol_html}</section>
    </div>
  </main>
  <footer>
    <p>{esc(t["sources"])}: {src}</p>
    <p>{esc(t["footer_cve"])}</p>
    <p>{esc(t["footer_time"])}</p>
    <p>{esc(t["footer_nvd"])}</p>
    <p>{esc(t["footer_analytics"])}</p>
  </footer>
</div>
<script src="{FONTS_JS}"></script>
<script>
(function () {{
  var KEY = "depweather:prefs";
  function prefs() {{ try {{ return JSON.parse(localStorage.getItem(KEY)) || {{}}; }} catch (e) {{ return {{}}; }} }}
  function save(patch) {{
    var cur = prefs();
    Object.keys(patch).forEach(function (k) {{ cur[k] = patch[k]; }});
    try {{ localStorage.setItem(KEY, JSON.stringify(cur)); }} catch (e) {{}}
  }}
  document.getElementById("theme").addEventListener("click", function () {{
    var root = document.documentElement;
    var dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    save({{ theme: root.dataset.theme }});
  }});
  document.querySelectorAll("a[data-lang]").forEach(function (a) {{
    a.addEventListener("click", function () {{ save({{ lang: a.getAttribute("data-lang") }}); }});
  }});
}})();
</script>
</body>
</html>
"""


_CSS = """:root {
  color-scheme: light;
  --page: #eef5fa; --surface: #ffffff; --ink: #12324d; --ink-2: #3f5b73; --muted: #62798d;
  --grid: #dce7ef; --border: rgba(18, 50, 77, 0.12); --accent: #1d6fb8; --group-head: #e6f0f7;
  --ok: #17703f; --ok-bg: #dcf2e4; --pend: #8a5200; --pend-bg: #fdecc8;
  --bad: #b3261e; --bad-bg: #fbe0dd; --dim-bg: #e9f0f5; --code-bg: #12242f; --code-ink: #dbe7f0;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) {
    color-scheme: dark;
    --page: #0d1b27; --surface: #12242f; --ink: #e4eef6; --ink-2: #b2c5d4; --muted: #8299ab;
    --grid: #1f3444; --border: rgba(228, 238, 246, 0.12); --accent: #6cb0ec; --group-head: #172c3a;
    --ok: #7fd9a2; --ok-bg: #153a27; --pend: #f2c36b; --pend-bg: #3d2f12;
    --bad: #ff9d94; --bad-bg: #4a1f1c; --dim-bg: #1a2e3c; --code-bg: #0a141c; --code-ink: #dbe7f0;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0d1b27; --surface: #12242f; --ink: #e4eef6; --ink-2: #b2c5d4; --muted: #8299ab;
  --grid: #1f3444; --border: rgba(228, 238, 246, 0.12); --accent: #6cb0ec; --group-head: #172c3a;
  --ok: #7fd9a2; --ok-bg: #153a27; --pend: #f2c36b; --pend-bg: #3d2f12;
  --bad: #ff9d94; --bad-bg: #4a1f1c; --dim-bg: #1a2e3c; --code-bg: #0a141c; --code-ink: #dbe7f0;
}
* { box-sizing: border-box; }
html, body { margin: 0; }
body {
  background: var(--page); color: var(--ink);
  font: 15px/1.5 "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", "Apple SD Gothic Neo", "Malgun Gothic", "Noto Sans KR", sans-serif;
  font-feature-settings: "calt" 0;
}
:lang(ko) body { word-break: keep-all; }
a { color: var(--accent); }
h1, h2, h4 { font-family: "Bricolage Grotesque", "IBM Plex Sans", system-ui, "Apple SD Gothic Neo", "Malgun Gothic", sans-serif; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 24px; }
@media (max-width: 767px) { .wrap { padding: 0 16px; } }
header.top { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; padding: 18px 0 6px; }
header.top h1 { margin: 0; font-size: 24px; font-weight: 800; }
header.top h1 a { color: inherit; text-decoration: none; display: flex; align-items: center; gap: 10px; }
header.top h1 img { width: 32px; height: 32px; }
.spacer { flex: 1; }
.controls { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.iconbtn { font: inherit; font-size: 13px; padding: 6px 12px; border: 1px solid var(--border); border-radius: 999px;
  background: var(--surface); color: var(--ink-2); cursor: pointer; text-decoration: none; }
.iconbtn.current { background: var(--ink); color: var(--page); }
.seg { display: inline-flex; border: 1px solid var(--border); border-radius: 999px; overflow: hidden; background: var(--surface); }
.seg a { font-size: 13px; padding: 6px 12px; color: var(--ink-2); text-decoration: none; }
.seg > * + * { border-left: 1px solid var(--border); }
.seg a[aria-current="page"] { background: var(--ink); color: var(--page); }
h1.pg { font-size: clamp(26px, 4vw, 38px); line-height: 1.15; margin: 14px 0 4px; letter-spacing: -0.02em; }
.lede { font-size: 16px; max-width: 70ch; margin: 4px 0; color: var(--ink-2); }
.meta { color: var(--muted); font-size: 13px; margin: 2px 0 14px; }
.cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 14px; }
@media (max-width: 640px) { .cards { grid-template-columns: 1fr; } }
.card3 { display: flex; align-items: center; justify-content: space-between; background: var(--surface);
  border: 1px solid var(--border); border-radius: 14px; padding: 12px 16px; }
.card3.amber { border-color: var(--pend); } .card3.red { border-color: var(--bad); }
.card3 .lab { display: block; font-size: 12.5px; color: var(--ink-2); }
.card3 .num { display: block; font: 700 28px/1.2 "Bricolage Grotesque", "IBM Plex Sans", sans-serif; }
.card3 .num small { font-size: 14px; font-weight: 500; margin-left: 2px; }
.ico { width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center; font-weight: 700; }
.ico.ok { background: var(--ok-bg); color: var(--ok); } .ico.pend { background: var(--pend-bg); color: var(--pend); }
.ico.bad { background: var(--bad-bg); color: var(--bad); }
.tools { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 10px; }
#q { flex: 1 1 320px; max-width: 480px; font: inherit; font-size: 14px; padding: 8px 12px; border: 1px solid var(--border);
  border-radius: 10px; background: var(--surface); color: var(--ink); }
.mine { font-size: 14px; color: var(--ink-2); cursor: pointer; }
.tablebox { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; }
.scroll-x { overflow-x: auto; }
table.tree { width: 100%; min-width: 860px; border-collapse: collapse; font-size: 13.5px; }
table.tree th, table.tree td { text-align: left; padding: 8px 10px; border-top: 1px solid var(--grid); vertical-align: middle; }
table.tree thead th { border-top: 0; color: var(--ink-2); font-size: 12.5px; font-weight: 600; white-space: nowrap; }
table.tree td.num, table.tree th.num { text-align: right; }
tr.lang th, tr.lang td { background: var(--group-head); }
tr.detail > td { background: var(--page); padding: 12px 14px; }
th.name { font-weight: 500; white-space: nowrap; }
th.lvl1 { padding-left: 28px; } th.lvl2 { padding-left: 52px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
.muted { color: var(--muted); } .small { font-size: 12px; }
.twisty { font: inherit; background: none; border: 0; color: inherit; cursor: pointer; padding: 2px 0; display: inline-flex; align-items: center; gap: 8px; text-align: left; }
.chev { width: 7px; height: 7px; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: rotate(-45deg); transition: transform .12s; flex: none; }
.twisty[aria-expanded="true"] .chev { transform: rotate(45deg); }
.twisty-gap { display: inline-block; width: 15px; }
.lmark { display: inline-grid; place-items: center; width: 22px; height: 22px; border-radius: 6px; color: #fff; font-size: 11px; font-weight: 700; }
.lsum { color: var(--ink-2); font-size: 13px; }
.pendtxt { color: var(--pend); font-weight: 600; } .badtxt { color: var(--bad); font-weight: 600; }
.cvecount { color: var(--bad); font-weight: 700; }
.star { background: none; border: 0; color: var(--muted); cursor: pointer; font-size: 15px; padding: 0 6px 0 0; }
.star[aria-pressed="true"] { color: #e0a100; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.pill.small { padding: 0 6px; font-size: 11.5px; }
.pill.ok { background: var(--ok-bg); color: var(--ok); } .pill.pend { background: var(--pend-bg); color: var(--pend); }
.pill.bad { background: var(--bad-bg); color: var(--bad); } .pill.warn { background: var(--pend-bg); color: var(--pend); }
.pill.dim, .pill.plain { background: var(--dim-bg); color: var(--ink-2); } .pill.lts { background: var(--dim-bg); color: var(--accent); font-size: 11px; }
.dgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
@media (max-width: 767px) { .dgrid { grid-template-columns: 1fr; } }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; min-width: 0; }
.card h4, .work h4 { margin: 0 0 6px; font-size: 14px; }
.cvelist { list-style: none; margin: 0; padding: 0; } .cvelist li { padding: 3px 0; }
table.mini { width: 100%; border-collapse: collapse; font-size: 12.5px; }
table.mini th, table.mini td { text-align: left; padding: 4px 8px 4px 0; border-top: 1px solid var(--grid); }
table.mini thead th { border-top: 0; color: var(--muted); font-weight: 600; }
.work { margin-top: 12px; padding: 10px 12px; border: 1px solid var(--pend); border-radius: 10px; background: var(--surface); }
.work pre { margin: 6px 0 0; padding: 10px; background: var(--code-bg); color: var(--code-ink); border-radius: 8px; overflow-x: auto; font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.bottom { display: grid; grid-template-columns: 1.4fr 1fr; gap: 12px; margin: 14px 0; }
@media (max-width: 767px) { .bottom { grid-template-columns: 1fr; } }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 12px 16px; }
.panel h2 { font-size: 17px; margin: 0 0 8px; }
.loglist, .eollist { list-style: none; margin: 0; padding: 0; }
.loglist li { display: flex; gap: 14px; padding: 5px 0; border-top: 1px solid var(--grid); }
.loglist li:first-child, .eollist li:first-child { border-top: 0; }
.eollist li { display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 6px 0; border-top: 1px solid var(--grid); }
.note { color: var(--muted); }
footer { color: var(--muted); font-size: 12.5px; padding: 8px 0 32px; }
footer p { margin: 4px 0; }
.js tr[hidden] { display: none; }
"""


def write_pages(data: dict, out: Path) -> list[Path]:
    written = []
    for lang in LANGS:
        dest = out / ("ko/patches/index.html" if lang == "ko" else "patches/index.html")
        if not dest.resolve().is_relative_to(out.resolve()):
            raise ValueError("patch page escapes output dir")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(render_page(data, lang, now=datetime.now(timezone.utc)), encoding="utf-8")
        written.append(dest)
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write the English and Korean runtime patch pages")
    p.add_argument("--patches", type=Path, default=ROOT / "data" / "patches.json")
    p.add_argument("--out", type=Path, required=True, help="Site root (not the repository)")
    args = p.parse_args(argv)
    try:
        data = json.loads(args.patches.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"patches page skipped: {e}", file=sys.stderr)
        return 0
    written = write_pages(data, args.out)
    print("wrote " + ", ".join(str(w) for w in written), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
