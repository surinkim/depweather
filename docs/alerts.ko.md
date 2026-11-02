# 알림

[English](alerts.md) | **한국어** · [README로 돌아가기](../README.ko.md)

새 권고를 받는 방법은 두 가지입니다. depweather 계정이 필요 없고, 누가 구독하는지도 저장하지 않습니다. 서버도 메일링 리스트도 없습니다. 이메일은 이 범위에 없습니다.

## Atom 피드

추적 중인 패키지의 새 권고는 사이트 피드에 모입니다.

**https://depweather.com/feed.xml**

페이지 `<head>`에 `<link rel="alternate" type="application/atom+xml">`가 있어서, 홈페이지 주소만 넣어도 피드 리더가 찾을 수 있습니다.

패키지마다 피드가 따로 있습니다. 경로는 `data/latest.json`의 패키지 키입니다. Maven 좌표의 `:`만 `~`로 바꿉니다. 이름에 `~`가 실제로 있으면 `~~`로 씁니다.

| 패키지 | 피드 |
|---|---|
| Next.js | https://depweather.com/feed/npm/next.xml |
| Django | https://depweather.com/feed/pypi/django.xml |
| Angular (`@angular/core`) | https://depweather.com/feed/npm/@angular/core.xml |
| Spring Boot | https://depweather.com/feed/maven/org.springframework.boot~spring-boot.xml |
| Gin | https://depweather.com/feed/go/github.com/gin-gonic/gin.xml |
| Symfony | https://depweather.com/feed/packagist/symfony/http-kernel.xml |

권고가 없어도 피드는 유효합니다. 다음 권고가 나오기 전에 구독해 두면 나중에 받아집니다.

항목 하나는 패키지 하나의 권고 하나입니다. `<id>`는 `tag:depweather.com,2026:advisory:` 뒤에 패키지 키와 권고 id를 붙인 값입니다. 스냅샷을 만든 시각은 넣지 않아서, 하루 두 번 다시 만들어도 같은 권고가 새 글로 보이지 않습니다. 예전 권고가 CISA KEV에 추가되면 id는 그대로 두고 `<updated>`만 추가된 날로 옮깁니다.

KEV 항목 제목은 `KEV ·`로 시작합니다. 치명 항목은 `Critical ·`, 악성 패키지 신고는 `Malicious ·`로 시작합니다. 다른 심각도도 피드에 있지만 접두어는 없습니다. 본문에는 원 권고, depweather의 해당 패키지, 그 패키지 피드 링크가 있습니다.

항목은 **14일** 동안 남습니다. 공개일이나 KEV 추가일 중 늦은 쪽부터 셉니다. 원본 스냅샷은 30일만 담고, 전체 피드는 최대 200건입니다. 패키지 피드는 그 기간의 항목을 모두 담습니다. 권고 문장은 영어입니다. upstream 데이터가 영어이기 때문입니다.

파일은 사이트를 배포할 때 `data/latest.json`으로 만듭니다(`python collect/feeds.py`). git에는 올리지 않습니다.

## 자기 저장소의 GitHub Actions

[`examples/depweather-alert.yml`](../examples/depweather-alert.yml)을 **자기** 저장소의 `.github/workflows/depweather.yml`로 복사한 뒤 커밋합니다. 같은 내용이 [재사용 액션](../alert/action.yml)이기도 합니다(`surinkim/depweather/alert`).

하루 한 번, 그리고 수동으로 실행할 때마다 다음을 합니다.

1. 저장소를 체크아웃하고 그 자리의 의존성 파일을 읽습니다. 파서는 웹사이트의 "내 스택"과 같은 [`js/stack.js`](../js/stack.js)입니다.
2. https://depweather.com/data/latest.json 을 받습니다.
3. 추적 패키지에 설정한 심각도 이상의 새 권고가 있으면 이슈를 엽니다.
4. 시크릿 `DEPWEATHER_WEBHOOK_URL`이 있으면 같은 알림을 Slack이나 Discord로 보냅니다.

매니페스트를 다른 곳으로 보내지 않습니다. 맞추는 작업은 GitHub 러너 안에서 끝납니다.

### 설정

1. 예제 파일을 `.github/workflows/depweather.yml`로 복사합니다.
2. 커밋하고 푸시합니다.
3. 선택: 저장소의 Settings → Secrets and variables → Actions → New repository secret. 이름은 `DEPWEATHER_WEBHOOK_URL`. Slack 인커밍 웹훅 주소나 Discord 웹훅 주소(`https://discord.com/api/webhooks/...`)를 넣습니다.
4. Actions → depweather → Run workflow로 예약 시각을 기다리지 않고 한 번 실행해 봅니다.

워크플로 토큰은 저장소를 읽고 이슈를 열 수 있습니다. 푸시할 수는 없고, `pull_request_target`도 없습니다. `actions/checkout`은 커밋 SHA에 고정하고 `persist-credentials`는 false라서 토큰이 `.git/config`에 남지 않습니다. 이 액션은 `GITHUB_TOKEN`을 스스로 보지 못하므로 환경 변수로 넘깁니다. 토큰은 출력하지 않습니다.

### 액션 고정

`@main`은 커밋마다 바뀝니다. 쓰지 마세요. 예제는 태그 `v1.0.0`을 가리킵니다. 같은 커밋에 `alert-v1` 태그도 붙입니다.

태그는 알림 코드가 `main`에 들어간 뒤, 그 머지 커밋에만 만들고 나중에 옮기지 않습니다. 호환이 깨지면 `v1.1.0`이나 `v2.0.0`을 새로 만듭니다. 유지 관리자가 실행합니다.

```sh
git fetch origin main
git tag -a v1.0.0 <머지-커밋-sha> -m "depweather alert action v1.0.0"
git tag -a alert-v1 <머지-커밋-sha> -m "depweather alert action v1"
git push origin v1.0.0 alert-v1
```

태그를 다시 달아도 실행 내용이 바뀌지 않게, 전체 커밋 SHA를 쓰는 편이 안전합니다. 주석에 버전을 남깁니다.

```yaml
uses: surinkim/depweather/alert@<v1.0.0의 40자 SHA> # v1.0.0
```

`git rev-parse v1.0.0`이 그 SHA입니다. 태그가 생기기 전에는 예제의 `alert@v1.0.0`이 실패합니다. `main`을 따라가지 않기 위해서입니다. [`examples/dependabot.yml`](../examples/dependabot.yml)을 `.github/dependabot.yml`로 복사하면, SHA로 고정한 액션에 새 버전이 나올 때 Dependabot이 풀 리퀘스트를 엽니다. 예제의 checkout은 `actions/checkout` v4.4.0 커밋에 고정되어 있습니다.

이 액션은 다른 액션을 `uses:`로 부르지 않습니다. GitHub 호스트 러너의 `node`만 실행합니다. 워크플로 입력은 셸 문장이 아니라 환경 변수입니다. `latest.json`의 제목, 요약, 패키지 이름, URL은 인자나 본문 파일로 이슈에 들어가며 셸이 확장하지 않습니다.

### 무엇을 새 권고로 보나

| 입력 | 기본값 | 의미 |
|---|---|---|
| `severity` | `critical` | `low`, `medium`, `high`, `critical`, `kev`. KEV는 항상 알립니다. 다만 `severity`가 `kev`이면 KEV만 알립니다. 악성 패키지 신고는 `kev`를 뺀 모든 단계에서 알립니다. |
| `days` | `7` | 공개일이나 KEV 추가일이 이 일수 안에 있어야 합니다. 30을 넘기면 30으로 줄입니다. 스냅샷이 가진 기간이 30일이기 때문입니다. |
| `open-issue` | `true` | 이슈를 열어 둡니다. `false`이고 웹훅이 있으면 이슈를 만든 뒤 바로 닫습니다. 다음 날 같은 알림을 다시 보내지 않기 위한 기록입니다. |
| `max` | `20` | 한 번에 보내는 새 알림 수. 나머지는 다음 실행으로 넘깁니다. |

### 같은 권고로 매일 이슈가 열리지 않습니다

이슈 본문에 `<!-- depweather-id:npm/next/GHSA-xxxx -->` 주석이 있고, 라벨은 `depweather`입니다. 다음 실행은 그 라벨이 붙은 이슈를 열린 것과 닫힌 것 모두 보고, 이미 기록된 id는 건너뜁니다.

이슈를 닫아도 다시 열리지 않습니다. 다시 알림을 받으려면 그 이슈를 삭제하세요.

`open-issue: false`에 웹훅만 켠 경우, 닫힌 이슈는 기록일 뿐입니다. 둘 다 끄면 일치 항목만 출력하고 기록하지 않아서, 다음 실행에서 다시 출력됩니다.

### Slack과 Discord

받는 주소는 https뿐이고, 주소 안에 사용자 이름이나 비밀번호가 있으면 거절합니다.

- Slack: `https://hooks.slack.com/services/...` (`hooks.slack-gov.com`도 가능)
- Discord: `https://discord.com/api/webhooks/...` (`discordapp.com`도 가능)

그 외는 거절합니다. 주소는 출력하지 않고, 거절했을 때의 오류 문구에도 넣지 않습니다. Discord는 `{"content": "..."}`, Slack은 `{"text": "..."}`로 보냅니다.

권고에서 온 문장은 한 줄로 만듭니다. `@everyone`, `@here`, `@channel`, `@user`의 `@`는 알림이 나가지 않게 다른 문자로 바꿉니다. HTML은 이스케이프합니다. 링크는 https이고 호스트가 depweather.com, osv.dev, github.com, nvd.nist.gov, cisa.gov일 때만 남깁니다. 데이터 주소는 `https://depweather.com/data/latest.json`만 받습니다.

이슈를 먼저 만들고 그다음 웹훅을 보냅니다. 웹훅이 실패하면 이슈가 이미 중복 방지 기록이므로 다음 실행은 웹훅을 다시 보내지 않습니다. 그 이슈를 지우고 워크플로를 다시 실행하세요.

### 처음 실행

아직 기록이 없으므로, 기간 안의 일치 항목이 모두 새 알림입니다. 이슈가 여러 개 열릴 수 있습니다. 이미 알고 있는 것은 닫으면 됩니다. 한 번에 최대 20개입니다.

### 읽는 파일

웹사이트의 "내 스택"과 같습니다. `package.json`(잠금 파일은 루트의 직접 의존성만), `requirements.txt`와 `requirements-*.txt`, `pyproject.toml`, `Pipfile`, `go.mod`, `Cargo.toml`, `pom.xml`, `Gemfile`, `composer.json`, `mix.exs`, NuGet `PackageReference` / `packages.config` / `*.csproj`.

`node_modules`, `vendor`, 그 밖의 빌드 디렉터리는 건너뜁니다. 이름은 그 생태계 안에서만 맞춥니다. PyPI는 PEP 503을 따릅니다. 웹사이트와 같은 `match` 별칭을 써서, Spring Boot 스타터는 Spring Boot로, Rails 구성 요소는 Rails로, Symfony 하위 패키지는 Symfony로 묶입니다.

### 한계

- depweather가 추적하는 패키지(약 150개)만 봅니다. 매니페스트에 있어도 그 밖은 무시합니다.
- 설치한 버전이 영향받는지는 보지 않습니다. 이슈에 권고의 수정 버전을 적어 두므로, 조치 전에 원 권고를 읽어야 합니다.
- Gradle, sbt, `pubspec.yaml`, `setup.py`, 잠금 파일의 전이 의존성은 읽지 않습니다. npm 잠금 파일은 루트 패키지의 직접 의존성만 봅니다.
- PHP, nginx, Node.js 같은 런타임·서버는 언어 매니페스트에 보통 없어서 이 알림에 잘 걸리지 않습니다. 그 패키지의 피드는 계속 갱신됩니다.
- 심각도는 원 권고의 값이며 틀릴 수 있습니다.
- 스냅샷은 하루 두 번 만들어지므로, 권고가 나온 뒤 몇 시간 뒤에야 보일 수 있습니다.
- 처음 실행하거나, 기록용 이슈를 지운 뒤의 실행은 기간 안의 항목을 다시 알립니다.
- 이름을 바꾼 포크나 비공개 레지스트리 이름은 맞지 않습니다.
- 웹훅만 써도 `issues: write`가 필요합니다. 반복을 막는 것이 닫힌 이슈이기 때문입니다.
- 이메일은 없습니다.

## 파일

- [`examples/depweather-alert.yml`](../examples/depweather-alert.yml) — 복사할 워크플로
- [`alert/action.yml`](../alert/action.yml) — 재사용 액션
- [`alert/check.js`](../alert/check.js) — 매칭과 심각도 규칙. `node --test tests/alert.test.js`
- [`collect/feeds.py`](../collect/feeds.py) — 피드 생성. `python tests/test_feeds.py`
