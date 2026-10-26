import sys
import os
import io
import re
import csv
import ssl
import time
import urllib.request
import concurrent.futures

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ctx = ssl._create_unverified_context()

SOURCE_CSV_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/Browser%20Extensions/browser_extensions_list.csv"
OUTPUT_CSV_PATH = "malicious_browser_extensions_list.csv"

TARGET_COLUMNS = [
    'browser_extension',
    'browser_extension_id',
    'metadata_category',
    'metadata_type',
    'metadata_link',
    'metadata_comment'
]

def fetch_source_rows():
    print(f"[*] 원본 CSV 다운로드 중: {SOURCE_CSV_URL}")
    req = urllib.request.Request(SOURCE_CSV_URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        content = resp.read().decode('utf-8', errors='ignore')
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)

def check_webstore_active(row):
    """
    조건 1: 크롬 웹 스토어에서 현재 설치 가능한(유효한) 확장 프로그램 확인
    """
    ext_id = (row.get('browser_extension_id') or '').strip().lower()
    url = f"https://chromewebstore.google.com/detail/{ext_id}?hl=en"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    
    max_retries = 2
    for _ in range(max_retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                canonical_match = re.search(r'<link\s+rel="canonical"\s+href="(.*?)"', body)
                canonical = canonical_match.group(1).strip() if canonical_match else ""
                
                title_match = re.search(r'<title>(.*?)</title>', body)
                raw_title = title_match.group(1).strip() if title_match else ""
                clean_title = re.sub(r'\s*-\s*Chrome Web Store$', '', raw_title, flags=re.IGNORECASE).strip()
                
                # 유효한 크롬 웹스토어 상세 페이지 확인
                if canonical and '/detail/' in canonical and clean_title and clean_title != "Chrome Web Store":
                    clean_row = {
                        'browser_extension': row.get('browser_extension', '').strip(),
                        'browser_extension_id': ext_id,
                        'metadata_category': row.get('metadata_category', '').strip(),
                        'metadata_type': row.get('metadata_type', '').strip(),
                        'metadata_link': row.get('metadata_link', '').strip(),
                        'metadata_comment': row.get('metadata_comment', '').strip()
                    }
                    return clean_row
                return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(1)
        except Exception:
            time.sleep(0.5)
            
    return None

def main():
    rows = fetch_source_rows()
    print(f"[*] 원본 CSV 전체 행: {len(rows)}개")
    
    candidates = []
    seen_ids = set()
    
    for r in rows:
        name = (r.get('browser_extension') or '').strip()
        eid = (r.get('browser_extension_id') or '').strip().lower()
        cat = (r.get('metadata_category') or '').strip()
        
        # [조건 2] 'browser_extension_id' 값이 비정상적인 것은 제외 (32자리 영문 소문자 a-p)
        if len(eid) != 32 or not re.fullmatch(r'[a-p]{32}', eid):
            continue
            
        # [조건 3] 'browser_extension' 값이 NULL이거나 N/A 제외
        if not name or name.lower() in ('null', 'n/a', 'na', 'none'):
            continue
            
        # [조건 4] 'metadata_category' 값이 PROXY, VPN, PROXY/VPN 제외
        cat_upper = cat.upper()
        if cat_upper in ('PROXY', 'VPN', 'PROXY/VPN') or 'PROXY/VPN' in cat_upper:
            continue
            
        if eid in seen_ids:
            continue
            
        seen_ids.add(eid)
        candidates.append(r)
        
    print(f"[*] 조건 2, 3, 4 충족 후보군: {len(candidates)}개 (스토어 실시간 검증 대상)")
    
    # [조건 1] 크롬 웹 스토어 설치 가능 여부 실시간 병렬 검증
    active_results = []
    start_time = time.time()
    total = len(candidates)
    completed = 0
    
    print(f"[*] 크롬 웹 스토어 실시간 검증 시작 (15 동시 스레드)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_row = {executor.submit(check_webstore_active, row): row for row in candidates}
        for future in concurrent.futures.as_completed(future_to_row):
            completed += 1
            res = future.result()
            if res:
                active_results.append(res)
            if completed % 100 == 0 or completed == total:
                elapsed = time.time() - start_time
                print(f"    - 진행률: {completed}/{total} 완료 ({len(active_results)}개 활성 확인됨) [{elapsed:.1f}초]")
                
    print(f"[+] 4가지 조건 모두 충족된 최종 데이터 수: {len(active_results)}개")
    
    # ID 기준으로 정렬
    active_results.sort(key=lambda x: x['browser_extension_id'])
    
    # Save to both filenames for full workflow compatibility
    for path in ['malicious_browser_extensions_list.csv', 'browser_extensions_list.csv']:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=TARGET_COLUMNS)
            writer.writeheader()
            writer.writerows(active_results)
        print(f"[+] CSV 저장 완료: {path}")
        
    # GitHub Actions output setting for blank.yml compatibility
    gh_output = os.environ.get('GITHUB_OUTPUT')
    if gh_output:
        try:
            with open(gh_output, 'a', encoding='utf-8') as f:
                f.write("has_changes=true\n")
        except Exception:
            pass

if __name__ == "__main__":
    main()
