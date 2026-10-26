import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import requests

SOURCE_RAW_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/Browser%20Extensions/browser_extensions_list.csv"
TARGET_FILE = "browser_extensions_list.csv"
COLUMNS = ['browser_extension', 'browser_extension_id', 'metadata_link', 'metadata_comment']

# 크롬 웹스토어 확인용 헤더 (봇 차단 방지)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

def is_chrome_extension_active(ext_id: str) -> bool:
    """크롬 웹스토어에서 해당 확장 프로그램이 실제로 설치 가능한지 확인"""
    if not ext_id or len(ext_id) != 32 or not ext_id.isalpha():
        # 일반적인 크롬 확장프로그램 ID는 32자리 알파벳 소문자
        return False

    url = f"https://chromewebstore.google.com/detail/{ext_id}"
    try:
        # allow_redirects=True로 확인하여 404나 홈으로 리다이렉트되는지 체크
        res = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        
        # 1. 상태 코드가 200이 아니면 삭제됨
        if res.status_code != 200:
            return False
            
        # 2. 리다이렉트되어 상세 페이지가 아닌 스토어 홈으로 튕긴 경우 제외
        if "/detail/" not in res.url:
            return False
            
        # 3. 페이지 내 삭제 안내 메시지 감지
        invalid_keywords = [
            "Item not found",
            "항목을 찾을 수 없습니다",
            "This item is not available",
            "an error occurred"
        ]
        if any(keyword in res.text for keyword in invalid_keywords):
            return False

        return True
    except requests.RequestException:
        return False

def check_extensions_parallel(id_list, max_workers=8):
    """ThreadPoolExecutor를 이용해 빠르게 병렬 검사"""
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
            except Exception as e:
                pass
            
            if done_count % 100 == 0 or done_count == total:
                print(f"진행률: {done_count}/{total} (현재 활성 발견: {len(active_ids)}개)")
            time.sleep(0.05) # Rate Limit 방지를 위한 미세 딜레이

    return active_ids

def sync_data():
    print("1. 원본 CSV 다운로드 중...")
    df_source = pd.read_csv(SOURCE_RAW_URL, dtype=str)
    
    # 컬럼 공백 정리 및 필터링
    df_source.columns = df_source.columns.str.strip()
    available_cols = [c for c in COLUMNS if c in df_source.columns]
    df_source = df_source[available_cols].dropna(subset=['browser_extension_id'])
    df_source = df_source.map(lambda x: str(x).strip() if pd.notna(x) else "")
    
    # ID 소문자 통일 및 중복 제거
    df_source['browser_extension_id'] = df_source['browser_extension_id'].str.lower()
    df_source = df_source.drop_duplicates(subset=['browser_extension_id'])

    # 2. 기존 파일 확인
    existing_ids = set()
    df_target = pd.DataFrame(columns=COLUMNS)
    
    if os.path.exists(TARGET_FILE):
        print("2. 기존 CSV 로드 중...")
        df_target = pd.read_csv(TARGET_FILE, dtype=str).fillna("")
        df_target.columns = df_target.columns.str.strip()
        df_target['browser_extension_id'] = df_target['browser_extension_id'].str.lower()
        existing_ids = set(df_target['browser_extension_id'].unique())
        print(f"-> 기존 등록된 확장 프로그램 수: {len(existing_ids)}개")

    # 3. 아직 내 저장소에 없는 '새로운 확장 프로그램 ID'만 추출
    source_ids = set(df_source['browser_extension_id'].unique())
    new_candidate_ids = list(source_ids - existing_ids)
    
    print(f"3. 새로 발견된 검사 대상 ID: {len(new_candidate_ids)}개")
    
    if not new_candidate_ids:
        print("새로운 확장 프로그램이 없습니다. 동기화를 종료합니다.")
        return False

    # 4. 신규 ID에 대해서만 웹스토어 활성 상태 검사
    active_ids = check_extensions_parallel(new_candidate_ids, max_workers=6)
    print(f"-> 신규 ID 중 크롬 웹스토어에 설치 가능한 확장 프로그램: {len(active_ids)}개")

    if not active_ids:
        print("신규 ID 중 현재 설치 가능한 확장 프로그램이 없습니다.")
        return False

    # 5. 활성화된 데이터만 필터링하여 결합
    df_new_active = df_source[df_source['browser_extension_id'].isin(active_ids)]
    df_final = pd.concat([df_target, df_new_active], ignore_index=True)
    df_final = df_final.drop_duplicates(subset=['browser_extension_id'])

    # 6. CSV 저장
    df_final.to_csv(TARGET_FILE, index=False, encoding='utf-8')
    print(f"4. 저장 완료! (총 저장된 활성 확장 프로그램: {len(df_final)}개)")
    return True

if __name__ == "__main__":
    has_changes = sync_data()
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"has_changes={'true' if has_changes else 'false'}\n")
