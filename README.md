# Malicious Browser Extensions List (Active in Chrome Web Store)

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
```bash
python push_to_github.py
```
- 실행 후 GitHub Personal Access Token(PAT)을 입력하면 대상 저장소(`NCITSSEC/malicious_browser_extensions_list`)로 자동 커밋 및 푸시됩니다.
