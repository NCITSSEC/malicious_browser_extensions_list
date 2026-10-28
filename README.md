# Malicious Browser Extensions List (Active in Chrome Web Store)

## 신규 판정 및 관측 이력

신규 알림은 직전 활성 CSV와의 차이가 아닌 `source_observations.json`의 원본 전체 ID 이력으로 판단합니다.

- 이력 파일이 없는 최초 실행은 원본 전체 ID를 기준선으로 등록하고 조건을 통과한 CSV를 생성합니다. 최초 실행에서는 메일을 보내지 않습니다.
- 이후 처음 관측한 ID가 4가지 조건과 제외 목록을 통과하면 CSV에 반영하고 한 번만 알립니다. 처음에는 조건을 충족하지 못했더라도 이후 충족하면 알립니다.
- 기준선 항목이나 이미 알린 항목은 스토어 재등장, 원본 삭제 후 재등록 시 다시 알리지 않습니다. 기존 항목의 메타데이터 변경도 신규 알림 대상이 아닙니다.
- CSV는 매일 전체 후보의 스토어 상태를 다시 확인한 결과입니다. 원본에서 제거되거나 제외 조건에 해당하는 항목은 CSV에서 빠지지만 관측 이력은 유지합니다.
- 타임아웃, 429, 서버 오류 또는 해석할 수 없는 응답은 확인 실패로 처리하고 실행을 중단합니다. 이 경우 CSV와 관측 이력을 갱신하지 않습니다. HTTP 404 또는 명시적인 사용 불가 문구는 비활성으로 판정합니다.
- 이력 파일을 삭제하면 기준선이 재생성되므로 저장소에 반드시 함께 커밋하고 보존하세요. 손상된 파일은 초기화하지 않고 오류로 중단합니다.
- 신규 알림은 이력 파일의 `pending_notifications`에 저장한 뒤 SMTP 발송을 시도합니다. 설정 누락이나 발송 실패 시 대기열을 보존하고 다음 성공 실행에서 재시도합니다. `notified`는 대기열 등록 여부이며 실제 발송 확인 시 `emailed_at`을 기록합니다.
- SMTP 발송 성공 후 확인 커밋이 실패하면 다음 실행에서 중복 발송될 수 있습니다. SMTP와 GitHub 커밋은 하나의 트랜잭션이 아니므로 엄밀한 단 한 번 발송을 보장하지는 않습니다.

`first_seen`은 이 모니터가 처음 관측한 KST 시각이며 업체의 등록일이나 악성 행위 시작일이 아닙니다. 기준선의 `first_seen` 역시 초기화 시각입니다. 초기화 이전 신규 여부는 이 파일로 소급 판정할 수 없습니다.

기존 운영 저장소에 도입할 때는 수정된 스크립트와 워크플로를 함께 반영한 후 수동 실행하세요. 첫 실행이 성공해야 기준선이 저장되며 그 이후부터 신규 ID를 구분합니다. 기존 CSV만으로 원본 전체의 과거 관측 여부를 복원할 수는 없습니다.

스케줄은 UTC 00:00, KST 09:00입니다. GitHub Actions의 예약 실행은 혼잡 시 지연되거나 누락될 수 있어 정확한 09:00 실행을 보장하지 않습니다.

스토어 검사는 대상 ID의 canonical URL과 페이지 본문의 `Add to Chrome` 표시를 확인합니다. 명시적인 사용 불가 문구나 HTTP 404는 비활성으로 처리합니다. 실제 설치 수행이나 국가·계정·브라우저 정책별 설치 허용까지 검증하는 방식은 아닙니다.

회귀 검증: `python -m unittest -v test_sync_extensions.py`

## 수정본 반영

배포 중 읽기 GET 요청은 성공하지만 `POST /git/trees`가 403/404로 실패하면 토큰의 쓰기 권한 또는 저장소 범위를 확인하세요. Fine-grained PAT는 Resource owner를 `NCITSSEC`로 설정하고 대상 저장소를 선택한 뒤 Contents, Workflows, Actions를 각각 Read and write로 설정해야 합니다. 조직에서 승인을 요구하면 승인 완료가 필요합니다. 공개 저장소에 Classic PAT를 사용하는 경우 `public_repo`와 `workflow` 범위가 필요합니다. 토큰 소유 계정 자체에도 해당 저장소의 쓰기 권한이 있어야 합니다.

PowerShell에서 `./deploy_to_github.ps1`을 실행하면 별도의 토큰 입력 창이 열립니다. 토큰을 붙여넣고 `배포 진행`을 누르면 로컬 테스트 후 코드와 워크플로를 하나의 커밋으로 반영하고, 워크플로 활성화 및 수동 실행을 요청합니다. 빈 값은 다시 입력받으며 취소하면 배포하지 않습니다. 기존 운영 CSV와 관측 이력은 업로드하지 않습니다. 자동 실행 시에만 `-UseEnvironmentToken` 옵션으로 `GITHUB_TOKEN` 환경 변수를 사용할 수 있습니다. 토큰은 대상 저장소의 Contents, Workflows, Actions 쓰기 권한이 필요하며 채팅이나 소스 파일에 저장하지 마세요. 첫 실행의 성공 여부는 Actions 화면에서 확인하세요.

[mthcht/awesome-lists](https://github.com/mthcht/awesome-lists/blob/main/Lists/Browser%20Extensions/browser_extensions_list.csv)의 확장 프로그램 데이터 중 아래 **4가지 조건을 모두 충족하는 활성 확장 프로그램 데이터만 선별**하여 보관하고, **GitHub Actions로 매일 1회 자동 동기화**하는 저장소입니다.

---

## 🎯 필터링 조건 (4가지)

1. **현재 크롬 웹 스토어에서 설치 가능한 확장 프로그램 (실시간 유효 상태)**
2. **`browser_extension_id` 값이 정상적인 32자리 크롬 확장 프로그램 ID만 포함 (비정상 값 제외)**
3. **`browser_extension` 값이 `NULL`이거나 `N/A`인 항목 제외**
4. **`metadata_category` 값이 `PROXY`, `VPN`, `PROXY/VPN`인 항목 제외**

---

## 📋 저장 데이터 필드 (`malicious_browser_extensions_list.csv`)

| 필드명 | 설명 |
|---|---|
| `browser_extension` | 브라우저 확장 프로그램 명칭 |
| `browser_extension_id` | 확장 프로그램 32자리 고유 ID |
| `metadata_category` | 카테고리 정보 (malware, compromised, scam, PUP 등) |
| `metadata_type` | 유형 정보 |
| `metadata_link` | 출처 분석 / 보고서 링크 |
| `metadata_comment` | 부가 설명 / 비고 |

---

## 🤖 GitHub Actions 매일 자동 동기화 (`.github/workflows/daily_sync.yml`)

- **실행 주기**: **매일 1회** (UTC 00:00 / 한국 시간 오전 09:00)
- **동작 방식**:
  1. 원본 저장소에서 최신 CSV를 자동으로 가져옵니다.
  2. 위 4가지 조건을 충족하는 데이터만 크롬 웹 스토어에서 실시간 재검증합니다.
  3. 원본이 업데이트되었거나 크롬 웹 스토어 상태가 변경되어 diff가 발생하면, GitHub Actions 봇이 자동으로 본 저장소에 커밋 및 푸시합니다.
  4. GitHub 웹의 **Actions** 탭에서 **Run workflow**를 눌러 언제든 수동으로 즉시 동기화할 수도 있습니다.

---

## 🛠️ 수동 실행 및 깃허브 업로드

### 1. 로컬에서 직접 검증 실행
```bash
python sync_extensions.py
```
- 실행 시 조건이 충족된 최신 `malicious_browser_extensions_list.csv`가 생성됩니다.

### 2. 개인 GitHub 저장소로 업로드
```powershell
./deploy_to_github.ps1
```
- 토큰을 숨김 입력하면 대상 저장소(`NCITSSEC/malicious_browser_extensions_list`)에 코드와 워크플로를 하나의 커밋으로 반영하고 워크플로 활성화 및 첫 실행을 요청합니다. 운영 CSV와 관측 이력은 보존합니다.
- 기존 `push_to_github.py`는 파일별 업로드 방식이므로 수정본 배포에는 위 PowerShell 스크립트를 사용하세요.
