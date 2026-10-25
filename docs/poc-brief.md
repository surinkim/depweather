`surinkim/depweather` 저장소(비공개, 지금은 README만 있음)에 depweather의 첫 POC를 만들어 주세요. 사용자와는 한국어 존댓말로 대화합니다.

## 배경
depweather는 인기 오픈소스 패키지의 최근 취약점을 생태계별 트리맵 한 장으로 보여주는 개인 오픈소스 정적 사이트입니다(수익화 없음, 글로벌 개발자 대상, 영문 UI). CVE 공개 건수가 1년 새 약 2.5배(NVD 기준 2025년 7월 3,933건 → 2026년 7월 9,919건)로 늘어 CVSS만으로는 우선순위를 가리기 어려워졌고, 그래서 KEV와 EPSS를 색에 반영합니다. 전체 CVE 건수·추이는 cve.icu가 이미 하고 있어 B 카운터는 보기 옵션으로만 두고, 패키지 기준 트리맵(A)과 패키지별 타임라인(C)이 차별점입니다. 화면 형태는 etfretro.kr ETF 지도(테마별 그룹, 크기=순자산, 색=수익률)를 참고합니다.

진행 순서는 POC → 비공개로 4주간 직접 사용 → 공개 전환과 도메인(depweather.com) 구매입니다. 제약: 서버·로그인·광고 없음, 사용자 저장소 스캔 기능 없음, 기본 패키지 목록에는 인기 패키지만 넣고 특정 회사 스택을 짐작하게 하는 목록은 넣지 않습니다.

기획 문서: https://claude.ai/artifact/CrMMhLRvTe1u77p7X85d6a (열람이 안 되면 이 브리프만으로 진행)

## 만들 것
1. 수집 스크립트 (Python 3.10+, 의존성 최소화, `collect/` 아래)
   - `stacks.yml`: 생태계별 인기 패키지 목록. npm, PyPI, Maven, Go 각 8~12개(예: npm next/react/express/axios/lodash/vite/undici, PyPI requests/django/numpy/jinja2/fastapi, Maven spring-web/jackson-databind/log4j-core/netty, Go stdlib/gin/grpc/golang.org/x/net). 인프라 그룹(kubernetes, openssl 등)은 OSV로 안 잡히면 POC에서는 빼고 README에 남겨 주세요.
   - OSV.dev: 각 패키지의 취약점(공개일, 요약, 영향·수정 버전, CVE 별칭, 심각도). OSV query API 또는 생태계별 덤프 중 단순한 쪽.
   - CISA KEV JSON, FIRST EPSS CSV로 각 CVE에 KEV 여부와 EPSS 점수를 붙임.
   - 인기도(타일 크기): npm downloads API, pypistats 또는 deps.dev. 못 구하는 생태계는 고정 가중치로 두고 README에 적기.
   - NVD API로 월별 CVE 공개 건수(최근 14개월)와 오늘/이번 달 건수. API 키가 없으면 느리게라도 동작하게.
   - 출력: `data/latest.json` 하나(생성 시각, 상단 숫자 4개, 생태계→패키지→최근 30일 취약점 목록, 월별 건수)와 `data/history/YYYY-MM-DD.json` 스냅샷.
2. `index.html` 한 장 (빌드 도구 없이 바닐라 JS + SVG, `data/latest.json`을 fetch)
   - 상단 숫자 4개: 오늘 신규 CVE, 이번 달 건수와 전년 동월 대비, KEV 신규(7일), 인기 스택 중 영향받은 패키지 수.
   - A 트리맵(기본 보기): 생태계별 그룹, 타일 크기 = 인기도, 색 = 최근 7일(토글로 30일) 최고 심각도. 회색=없음, 노랑=중간, 주황=높음, 빨강=치명 또는 KEV. EPSS가 높으면 한 단계 올리는 규칙은 상수 하나로 두고 기본은 끔. 'KEV만' 필터.
   - C 타임라인: 타일 클릭이나 검색 시 패키지별 30일 타임라인에 취약점을 점으로, 오른쪽에 수정 버전. 화면 폭 768px 미만이면 기본 보기.
   - B 카운터: 보기 옵션. 월별 막대 + 생태계별 7일 신규/치명/KEV 표.
   - 보기 상태는 URL에(`?view=a|b|c`, `?pkg=npm/next`), 마지막 선택은 localStorage(try/catch).
   - 라이트/다크 모드, 모바일에서 가로 스크롤 없음.
   - 하단 출처 표기: OSV, GitHub Advisory Database(CC-BY 4.0), CISA KEV, FIRST EPSS, 그리고 NVD 문구 "This product uses the NVD API but is not endorsed or certified by the NVD."
3. `.github/workflows/collect.yml`: 하루 1회 cron + 수동 실행으로 수집 후 `data/` 커밋. 저장소가 비공개라 GitHub Pages 배포는 아직 붙이지 말고, 공개 전환 뒤 추가할 단계로 README에 적기.
4. README(영문): 무엇을 보여주는지, 색 기준, 데이터 출처와 라이선스, 로컬 실행 방법. 코드 라이선스는 MIT(LICENSE 파일 추가).

## 완료 기준
- `python collect/collect.py` 한 번으로 `data/latest.json`이 실제 데이터로 생성된다.
- `python -m http.server`로 `index.html`을 열면 A/B/C 세 보기가 실제 데이터로 그려지고 전환된다. 스크린샷으로 확인.
- 변경을 커밋하고 main에 푸시한다(개인 프로젝트라 브랜치·PR 없이 main 직접 작업).

## 확인하고 README에 적을 것
KEV, EPSS, deps.dev 이용 조건 원문. 확인하지 못하면 '확인 필요'로 남기기.
