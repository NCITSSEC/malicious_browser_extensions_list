import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import requests

SOURCE_RAW_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/Browser%20Extensions/browser_extensions_list.csv"
TARGET_FILE = "browser_extensions_list.csv"
COLUMNS = ['browser_extension', 'browser_extension_id', 'metadata_link', 'metadata_comment']

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

def is_chrome_extension_active(ext_id: str) -> bool:
    """크롬 웹스토어에서 실제 설치 가능한 확장 프로그램인지 정확하게 검증"""
    if not ext_id or not isinstance(ext_id, str):
        return False
    
    ext_id = ext_id.strip().lower()
    
    # 크롬 확장 ID는 정확히 32자리의 알파벳 소문자(a-p)로 구성됨
    if len(ext_id) != 32 or not ext_id.isalpha():
        return False

    url = f"https://chromewebstore.google.com/detail/{ext_id}?hl=en"
    
    try:
        # allow_redirects=True로 요청
        res = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        
        # 1. 상태 코드가 200이 아니면 삭제된 것
        if res.status_code != 200:
            return False

        # 2. detail URL이 아니면 홈 등으로 튕긴 것 (삭제됨)
        if f"/detail/{ext_id}" not in res.url:
            return False

        # 3. 신규 크롬 웹스토어의 핵심 삭제 시그니처 검사
        # 삭제/비공개된 확장의 경우 페이지 타이틀이 기본 상호명("Chrome Web Store")이거나 에러 문구가 포함됨
        html_text = res.text

        # 삭제된 항목 대표 패턴
        not_found_patterns = [
            "Item not found",
            "item is not available",
            "An error occurred",
            "<title>Chrome Web Store</title>",  # 정상 항목은 <title>확장이름 - Chrome Web Store</title> 형태임
            "c-wiz", # 빈 c-wiz 컨테이너 체크용
        ]

        if "<title>Chrome Web Store</title>" in html_text:
            return False

        if "Item not found" in html_text or "This item is not available" in html_text:
            return False

        # 4. 정상 등록된 확장 페이지에 반드시 존재하는 설치 버튼/메타 속성 확인
        # 정상적인 확장 프로그램 상세 페이지에는 og:title에 확장 프로그램 이름이 들어감
        if 'property="og:title"' in html_text and 'content="Chrome Web Store"' not in html_text:
            return True
            
        # 메타 태그가 정상인 경우
        if f'https://chromewebstore.google.com/detail/{ext_id}' in html_text:
            # Add to Chrome (Chrome에 추가) 관련 요소가 있는지 확인
            if "Add to Chrome" in html_text or "chrome.google.com/webstore" in html_text:
                return True

        return False

    except Exception:
        return False

def check_extensions_parallel(id_list, max_workers=10):
    """ThreadPoolExecutor를 이용한 병렬 검사"""
    active_ids = set()
    total = len(id_list)
    print(f"총 {total}개의 확장 프로그램 상태를 크롬 웹스토어에서 검증합니다...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_id = {executor.submit(is_chrome_extension_active, ext_id): ext_id for ext_id in id_list}
        done_count = 0
        
        for future in as_completed(future_to_id):
            ext_id = future_to_id[future]
            done_count += 1
            try:
                if future.result():
                    active_ids.add(ext_id)
            except Exception:
                pass
            
            if done_count % 100 == 0 or done_count == total:
                print(f"진행률: {done_count}/{total} (현재 활성 확정: {len(active_ids)}개)")
            time.sleep(0.03)

    return active_ids

def sync_data():
    print("1. 원본 CSV 다운로드 중...")
    df_source = pd.read_csv(SOURCE_RAW_URL, dtype=str)
    
    # 컬럼 정리
    df_source.columns = df_source.columns.str.strip()
    available_cols = [c for c in COLUMNS if c in df_source.columns]
    df_source = df_source[available_cols].dropna(subset=['browser_extension_id'])
    df_source = df_source.map(lambda x: str(x).strip() if pd.notna(x) else "")
    
    df_source['browser_extension_id'] = df_source['browser_extension_id'].str.lower()
    df_source = df_source.drop_duplicates(subset=['browser_extension_id'])

    # 기존 타겟 파일 확인
    existing_ids = set()
    df_target = pd.DataFrame(columns=COLUMNS)
    
    if os.path.exists(TARGET_FILE):
        print("2. 기존 CSV 로드 중...")
        df_target = pd.read_csv(TARGET_FILE, dtype=str).fillna("")
        df_target.columns = df_target.columns.str.strip()
        df_target['browser_extension_id'] = df_target['browser_extension_id'].str.lower()
        existing_ids = set(df_target['browser_extension_id'].unique())
        print(f"-> 기존 등록된 확장 프로그램 수: {len(existing_ids)}개")

    # 신규 검사 대상 ID 추출
    source_ids = set(df_source['browser_extension_id'].unique())
    new_candidate_ids = list(source_ids - existing_ids)
    
    print(f"3. 새로 검사할 대상 ID: {len(new_candidate_ids)}개")
    
    if not new_candidate_ids:
        print("새로운 확장 프로그램이 없습니다. 동기화를 종료합니다.")
        return False

    # 웹스토어 상태 검증
    active_ids = check_extensions_parallel(new_candidate_ids, max_workers=10)
    print(f"-> 검사 완료: 실제 활성(설치 가능) 확장 프로그램: {len(active_ids)}개")

    if not active_ids:
        print("설치 가능한 확장 프로그램이 없습니다.")
        return False

    # 활성 확장 프로그램 데이터만 필터링 후 저장
    df_new_active = df_source[df_source['browser_extension_id'].isin(active_ids)]
    df_final = pd.concat([df_target, df_new_active], ignore_index=True)
    df_final = df_final.drop_duplicates(subset=['browser_extension_id'])

    df_final.to_csv(TARGET_FILE, index=False, encoding='utf-8')
    print(f"4. 저장 완료! (최종 활성 확장 수: {len(df_final)}개)")
    return True

if __name__ == "__main__":
    has_changes = sync_data()
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"has_changes={'true' if has_changes else 'false'}\n")
