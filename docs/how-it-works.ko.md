# depweather 작동 방식

[English](how-it-works.md) | **한국어** · [README로 돌아가기](../README.ko.md)

페이지 뒤의 자세한 내용입니다. 각 보기가 보여주는 것, 색과 심각도를 정하는 방법, 패키지를 고르는 기준, 데이터 출처를 담았습니다.

## 보여주는 것

**상단 숫자**

| 숫자 | 의미 |
|---|---|
| 오늘 신규 CVE | UTC 00:00 이후 NVD에 공개된 CVE(거부된 CVE 제외) |
| 이번 달 CVE | 이번 달 지금까지 NVD에 공개된 CVE와 작년 같은 달(한 달 전체) 대비 증감 |
| CISA KEV 신규(7일) | 최근 7일 동안 KEV 목록에 추가된 항목(모든 벤더) |
| 영향받은 인기 패키지 | 최근 7일 안에 공개된 권고가 하나 이상 있는 추적 패키지 수 |

**A. 트리맵(기본 보기).** 생태계마다 테두리를 두른 그룹 하나씩입니다. npm, PyPI,
Maven, NuGet, crates.io, Packagist, Go, RubyGems, Hex와 "Runtimes & servers"
(패키지 149개)로 구성됩니다. 그룹 면적은 [Stack Overflow Developer Survey 2026](https://survey.stackoverflow.co/2026/technology/data)
응답자 중 해당 언어를 쓰는 비율입니다(JavaScript 62.0%, Python 58.0%, Java 27.6%,
C# 27.1%, Rust 18.0%, PHP 17.7%, Go 16.5%, Ruby 5.8%, Elixir 2.6%). 작은 그룹도
찾을 수 있게 최소 3.5%를 보장합니다. "Runtimes & servers"는 특정 언어에 대응하지
않아 고정 면적을 씁니다(`stacks.yml`의 `area: 20`). 그룹 안에서 타일 크기는
패키지 다운로드 수입니다("데이터 출처" 참고. Maven, NuGet, Go, "Runtimes & servers"는
같은 크기). 타일 색은 최근 7일(30일로 전환 가능) 동안 *공개된* 권고 중 가장 심각한
것입니다. "KEV만"을 켜면 CVE가 CISA KEV 목록에 있는 권고만 남깁니다.

큰 화면에서는 트리맵이 창 높이 대부분을 채우고 "전체 화면" 버튼이 있습니다. 핀치,
Ctrl/⌘ + 스크롤, 더블클릭(Shift + 더블클릭은 축소), +/− 버튼, +/−/0 키로 확대·축소하고
드래그로 이동합니다. 글자는 화면 기준으로 같은 크기라서 타일이 커질수록 더 많은 정보가
보입니다. 이름 → 권고 수 → 심각도별 개수와 수정 버전 → 가장 심각한 권고와 요약, 다운로드
수, 설문 비율 순입니다.

**C. 타임라인.** 타일을 누르거나 패키지를 검색하면 열립니다. 최근 30일의 권고를
공개일 위치에 점으로 찍고, 오른쪽에 수정 버전, 아래에 권고 표를 보여줍니다. 화면 폭이
768px보다 좁으면 기본 보기입니다.

**B. 카운터(보기 옵션).** 최근 14개월의 월별 NVD CVE 건수, 생태계별 7일 표(신규/치명/KEV),
이번 주 KEV 추가 목록입니다. 전체 CVE 건수는 [cve.icu](https://cve.icu)가 이미 잘 하고
있어서, 이 보기는 보조 패널입니다.

화면은 영어와 한국어를 지원합니다(오른쪽 위 EN / KO. 처음 방문하면 브라우저 언어를
따릅니다). 데이터에서 온 권고 내용은 영어 그대로입니다.

보기 상태는 URL에 남아서(`?view=a|b|c`, `?pkg=npm/next`, `&range=30`, `&kev=1`,
`&lang=ko`) 링크로 공유할 수 있습니다. 마지막으로 고른 보기, 기간, 언어, 테마는
`localStorage`에 기억합니다. 페이지 하단에 페이지 버전이 표시되어 브라우저 캐시에 남은
예전 화면을 알아보기 쉽습니다(Cmd/Ctrl + Shift + R로 새로고침).

## 색과 날씨

페이지는 일기예보처럼 읽힙니다. 맨 위 문장은 데이터로 만듭니다("Storms over npm, PyPI
and 3 more, with critical issues in pillow, MariaDB, nginx and 6 more."). 그 아래 띠는
그룹마다 가장 심각한 패키지의 날씨를 보여주고, 그룹을 누르면 지도가 그 그룹으로
확대됩니다.

| 날씨 | 색 | 의미 |
|---|---|---|
| 맑음(해) | 회색 타일 | 기간 안에 권고 없음 |
| 흐림(구름) | 노랑 | 낮음 또는 중간, 또는 어느 출처에도 심각도가 없음 |
| 비(비구름) | 주황 | 높음 |
| 폭풍(번개 구름) | 빨강 | 치명, 또는 악성 패키지 보고(OSV `MAL-`) |
| 실제 악용(마젠타 번개 구름) | 마젠타 | CVE가 CISA KEV에 있음 |

영향받은 타일에는 날씨 아이콘이 붙고, 타임라인 점은 심각도에 따라 모양이 바뀝니다
(동그라미, 삼각형, 마름모). 그래서 심각도를 색만으로 구분하지 않습니다.

심각도는 다음 순서로 정합니다. GitHub Advisory 심각도 → OSV 벡터로 계산한 CVSS v3 점수
→ NVD CVSS 기본 심각도(Go 표준 라이브러리처럼 아직 등급이 없는 권고만 조회) →
"알 수 없음"(노랑으로 표시). OSV가 같은 문제를 여러 ID(`GO-`, `PYSEC-`, `GHSA-`)로
올린 경우 하나로 합치고 가장 높은 심각도를 씁니다.

EPSS는 툴팁과 표에 표시합니다. EPSS 점수가 높으면 색을 한 단계 올리는 규칙이 있지만
기본은 꺼져 있고, `index.html` 스크립트 맨 위의 상수 `EPSS_BUMP_THRESHOLD`로 조절합니다
(예: `0.1`).

## 패키지

기본 목록 [`collect/stacks.yml`](../collect/stacks.yml)에는 패키지 149개가 있습니다.
언어 레지스트리에서 136개, 런타임과 서버가 13개입니다. 생태계마다 언어의 설문 비율에
맞춰 대략의 개수를 정했습니다(npm·PyPI 24, Maven 18, NuGet·crates.io·Packagist·Go 14,
RubyGems 8, Hex 6). 다음 순서로 고릅니다.

1. **사람들이 쓴다고 답한 프레임워크.** Stack Overflow 2026 "Web frameworks and
   technologies"에서 응답자 2% 이상이고 OSV 생태계의 패키지로 배포되는 것은 모두
   넣었습니다(React 41.5%, Next.js 20.6%, ASP.NET Core 19.9%, jQuery 19.7%,
   FastAPI 18.5%, Vue.js 17.2%, Angular 16.0%, Express 15.6%, Spring Boot 12.8%,
   Flask 12.5%, Django 11.3%, Svelte, Laravel, Blazor, Astro, AngularJS, NestJS,
   Ruby on Rails, SvelteKit, htmx, Nuxt, Deno, Symfony, Axum, Fastify, Hono, Phoenix,
   Drupal). 비율은 `survey:`에 저장하고 타일에 표시합니다.
2. **레지스트리 다운로드 상위 패키지.** 순위가 공개된 곳에서 고릅니다.
   [top-pypi-packages](https://github.com/hugovk/top-pypi-packages)(PyPI), crates.io
   최근 다운로드, Packagist "popular", hex.pm 최근 다운로드. 타입 스텁, polyfill,
   플랫폼 전용 패키지(`windows_*` 크레이트), 테스트 전용 도구는 제외합니다.
3. **순위가 공개되지 않은 곳**(npm, Maven, Go, NuGet, RubyGems): 취약점 이력이 있는
   널리 쓰이는 라이브러리(HTTP, 파싱, 암호화, 인증, 직렬화)를 직접 골랐습니다. 매일
   수집할 때 npm, PyPI, crates.io, Packagist, RubyGems, Hex의 실제 다운로드 수를
   기록하므로, 데이터를 보고 바꿀 수 있습니다.

**런타임과 서버**(PHP, Node.js, Python, Java, Ruby, WordPress, nginx, Apache httpd,
Tomcat, PostgreSQL, MariaDB, Redis, MongoDB)는 컨테이너 이미지 단위로 추적하는 OSV의
Bitnami 생태계에서 가져옵니다. 이들의 권고는 언어 레지스트리에 없습니다. 예를 들어
PHP2Shell(CVE-2026-109618, CVE-2026-109619, 2026년 10월)은 PHP 자체의 결함이라
Packagist 그룹이 아니라 PHP 타일에 나타납니다.

어떤 제품은 OSV에 여러 패키지 이름으로 등록됩니다. 타일 하나가 여러 이름이나 이름
접두어와 매칭될 수 있습니다(`stacks.yml`의 `match:`). ASP.NET Core는
`Microsoft.AspNetCore.*`(플랫폼별 런타임 팩 포함), .NET은
`Microsoft.NETCore.App.Runtime.*`, Symfony는 `symfony/*`, Ruby on Rails는
`actionpack`, `activerecord`, `activestorage` 등 Rails 젬을 묶습니다.

목록에는 널리 쓰이는 패키지만 넣습니다. 특정 회사의 스택을 짐작하게 하는 목록은
넣지 않습니다. 추가 제안은 풀 리퀘스트로 받습니다. 개인 목록을 커밋하지 않고
추적하려면 수집기에 다른 파일을 지정하세요.

```sh
DEPWEATHER_STACKS=~/my-stacks.yml python collect/collect.py
```

아직 다루지 않는 것:

- **OpenSSL 등 시스템 라이브러리.** OSV의 Bitnami 데이터에 없습니다. NVD CPE 매칭이나
  리눅스 배포판 피드가 필요합니다. Kubernetes는 Go 모듈 `k8s.io/kubernetes`로
  추적합니다.
- **구형 ASP.NET(.NET Framework).** OSV 생태계의 패키지가 아닙니다.
- **Swift(SwiftURL)와 Dart(Pub).** 아직 OSV에 권고가 적습니다.
- **목록 밖 패키지 검색.** 지금은 추적 중인 패키지만 검색됩니다.
- **CVE 없이 나온 보안 수정**(릴리스 노트). 기획 단계의 아이디어입니다.

## 데이터 출처와 라이선스

| 출처 | 쓰임 | 받는 방법 | 이용 조건 |
|---|---|---|---|
| [OSV.dev](https://osv.dev) | 권고, 영향·수정 버전, 별칭 | `osv-vulnerabilities.storage.googleapis.com`의 생태계별 내보내기(`modified_id.csv`로 기간 안에 바뀐 항목을 찾고 항목마다 JSON 하나) | 각 항목은 원 데이터베이스의 라이선스를 따릅니다. **확인 필요**: OSV 데이터 라이선스 페이지를 작성 환경에서 열 수 없었습니다 |
| [Bitnami Vulnerability Database](https://github.com/bitnami/vulndb) | 런타임·서버 그룹(OSV 경유) | — | Apache License 2.0(`bitnami/vulndb` README, 2026-10-25 확인) |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | npm / PyPI / Maven / Go 권고 대부분(OSV 경유) | — | CC-BY 4.0(저장소의 `LICENSE.md`, 2026-10-25 확인). 페이지 하단에 출처 표기 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 실제 악용 여부, 7일 신규 | `known_exploited_vulnerabilities.json`, 실패하면 CISA의 GitHub 미러 `cisagov/kev-data` | CC0 1.0. `cisagov/kev-data` LICENSE 원문(2026-10-25 확인): "The KEV database is distributed under the Creative Commons 0 1.0 License. You may use this data in any legal manner but note that information provided at any 3rd party links included in the KEV database are bound by the policies and licenses of those 3rd party websites. Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS." |
| [FIRST EPSS](https://www.first.org/epss/) | CVE별 악용 확률 | `epss_scores-current.csv.gz` | **확인 필요.** FIRST EPSS 이용 약관의 2차 사본에 따르면 점수는 누구나 무료로 쓸 수 있고, 가능하면 EPSS 출처 표기를 요청합니다. first.org 원문은 작성 환경에서 열 수 없었습니다 |
| [NVD API 2.0](https://nvd.nist.gov/developers) | 월별·일별 CVE 건수, 등급 없는 권고의 CVSS | `/rest/json/cves/2.0` | 필수 문구: "This product uses the NVD API but is not endorsed or certified by the NVD."(페이지 하단). 키 없이 약 6.5초당 1회로 동작하고, `NVD_API_KEY`를 설정하면 빨라집니다 |
| npm 다운로드 API, [pypistats](https://pypistats.org) | 타일 크기: 지난주 다운로드 | `api.npmjs.org/downloads/point/last-week/…`, `pypistats.org/api/packages/…/recent` | **확인 필요** |
| crates.io, Packagist, RubyGems, hex.pm API | 타일 크기: crates.io 90일, Packagist 30일, RubyGems 누적, Hex 지난주 다운로드 | `crates.io/api/v1/crates/…`(초당 1회, 식별 가능한 User-Agent), `packagist.org/packages/….json`, `rubygems.org/api/v1/gems/….json`, `hex.pm/api/packages/…` | **확인 필요** |
| Bricolage Grotesque, IBM Plex Sans | 서체. `fonts/`에 직접 두어 외부 요청이 없습니다 | Google Fonts에서 한 번 받음 | SIL Open Font License 1.1(`fonts/OFL-*.txt`) |
| [Stack Overflow Developer Survey 2026](https://survey.stackoverflow.co/2026/technology/data) | 그룹 면적, 프레임워크 선정과 비율 | 숫자를 `stacks.yml`에 직접 옮김 | **확인 필요**(설문 공개 데이터는 보통 Open Database License로 배포됩니다) |
| [deps.dev](https://deps.dev) | 아직 쓰지 않음(Maven / Go 인기도 후보) | — | 자체 생성 데이터는 CC-BY 4.0, API는 Google API 서비스 약관 적용, 캐시는 명시적으로 허용(`google/deps.dev` README, 2026-10-25 확인) |

그룹마다 한 가지 지표를 쓰므로 타일 크기는 같은 그룹 안에서만 비교됩니다. Maven과
Go는 공개된 다운로드 수가 없고, NuGet 검색 API(다운로드 수 제공)는 작성 환경에서
접속할 수 없어서, 이 셋은 고정 가중치를 씁니다(`stacks.yml`의 `weight:`, 기본 1).
다운로드 API가 실패하면 같은 고정 가중치로 대신하고, 페이지에 어떤 기준으로 크기를
정했는지 표시합니다.

출처에 접속하지 못하면 해당 값을 `null`로 쓰고 `latest.json`의 `sources`에 실패를
기록합니다. 페이지는 숫자 대신 안내 문구를 보여줍니다. NVD가 안 될 때는 이전 실행의
월별 건수를 재사용합니다.

## 데이터 파일

- `data/latest.json`: 페이지가 그리는 모든 것. 생성 시각, 상단 숫자, 생태계 → 패키지 →
  최근 30일 권고(KEV, EPSS, 수정 버전 포함), 월별 NVD 건수, 이번 주 KEV 추가 목록.
- `data/history/YYYY-MM-DD.json`: 날마다 남기는 사본. 나중에 전날 대비 변화를 계산하는
  데 씁니다.

## 로컬 실행

Python 3.10 이상이 필요합니다.

```sh
pip install -r collect/requirements.txt   # PyYAML만 필요
python collect/collect.py                 # data/latest.json 생성(약 5분, 대부분 NVD 요청 간격 대기)
python -m http.server                     # 브라우저에서 http://localhost:8000/ 열기
```

`index.html`은 빌드 단계와 의존성이 없습니다. 같은 폴더의 `data/latest.json`을 불러옵니다.

## 매일 수집

[`.github/workflows/collect.yml`](../.github/workflows/collect.yml)이 매일 06:17 UTC(한국
시간 15:17)와 수동 실행 시(Actions → collect → Run workflow) 돌고 `data/`를 커밋합니다.
NVD 호출을 빠르게 하려면 저장소 시크릿 `NVD_API_KEY`를 추가하세요(선택).

### 공유 미리보기

`og.png`(1200x630)는 링크 미리보기 이미지입니다.
[`og/og-template.html`](../og/og-template.html)을 `node og/render.js`(Playwright)로
그립니다. 링크 미리보기는 오래 캐시되고 데이터는 매일 바뀌므로, 실제 패키지가 아닌
생태계 이름만 보여줍니다. `index.html`의 `og:url`과 `og:image`는 depweather.com을
가리킵니다.

### 배포

[`.github/workflows/pages.yml`](../.github/workflows/pages.yml)이 `main`에 푸시할 때와
수집이 성공할 때마다 GitHub Pages에 배포합니다. 페이지가 불러오는 파일만 올립니다
(`index.html`, `favicon.svg`, `og.png`, `fonts/`, `data/latest.json`).

처음 한 번 설정: Settings → Pages → Source를 GitHub Actions로 하고, Custom domain에
`depweather.com`을 넣은 뒤 "Enforce HTTPS"를 켭니다. 도메인 등록 업체의 DNS에는 `@`의
`A` 레코드 4개(185.199.108.153, 185.199.109.153, 185.199.110.153, 185.199.111.153)와
`www`의 `CNAME` 레코드(`surinkim.github.io`)를 넣습니다.
