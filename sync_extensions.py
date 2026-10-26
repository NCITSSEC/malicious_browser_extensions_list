import sys
import os
import io
import re
import csv
import ssl
import time
import json
import urllib.request
import concurrent.futures

# 콘솔 출력 UTF-8 인코딩 설정
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ctx = ssl._create_unverified_context()

SOURCE_CSV_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/Browser%20Extensions/browser_extensions_list.csv"
OUTPUT_CSV_PATH = "malicious_browser_extensions_list.csv"
REPORT_HTML_PATH = "new_extensions_report.html"
EXCLUDE_LIST_PATH = "exclude_list.txt"

TARGET_COLUMNS = [
    'browser_extension',
    'browser_extension_id',
    'metadata_category',
    'metadata_type',
    'metadata_link',
    'metadata_comment'
]

# 기본 제외 ID 목록 (Chrome Remote Desktop, AdBlock, Google Translate 등 정상 확장 프로그램)
DEFAULT_EXCLUDE_IDS = {
    'inomeogfingihgjfjlpeplalcfajhgai',  # Chrome Remote Desktop
    'gighmmpiobklfepjocnamgkkbiglidom',  # AdBlock
    'aapbdbdomjkkjkaonfhkkikfgjllcleb'   # Google Translate
}

def load_exclude_ids():
    """
    제외할 확장 프로그램 ID 목록 로드 (기본 세트 + exclude_list.txt)
    """
    exclude_ids = set(DEFAULT_EXCLUDE_IDS)
    if os.path.exists(EXCLUDE_LIST_PATH):
        try:
            with open(EXCLUDE_LIST_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # 주석(#) 분리 및 ID 추출
                    eid = line.split('#')[0].strip().lower()
                    if len(eid) == 32 and re.fullmatch(r'[a-p]{32}', eid):
                        exclude_ids.add(eid)
        except Exception as e:
            print(f"[!] 제외 목록 파일 로드 중 경고: {e}")
            
    print(f"[*] 총 {len(exclude_ids)}개의 제외 대상 ID가 설정되었습니다.")
    return exclude_ids

def load_existing_ids():
    """
    기존에 저장되어 있던 CSV 파일에서 이미 등록된 ID 목록 추출
    """
    if not os.path.exists(OUTPUT_CSV_PATH):
        return set()
    try:
        with open(OUTPUT_CSV_PATH, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            return set(r['browser_extension_id'].strip().lower() for r in reader if r.get('browser_extension_id'))
    except Exception:
        return set()

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

def generate_email_html(new_items):
    """
    신규 발견된 악성 확장 프로그램에 대한 깔끔한 HTML 메일 본문 생성
    """
    rows_html = ""
    for item in new_items:
        store_url = f"https://chromewebstore.google.com/detail/{item['browser_extension_id']}"
        ref_link = f"<a href='{item['metadata_link']}' target='_blank'>링크</a>" if item['metadata_link'] else "-"
        rows_html += f"""
        <tr>
            <td style="padding: 10px; border: 1px solid #ddd; font-weight: bold;">{item['browser_extension']}</td>
            <td style="padding: 10px; border: 1px solid #ddd; font-family: monospace;">
                <a href="{store_url}" target="_blank">{item['browser_extension_id']}</a>
            </td>
            <td style="padding: 10px; border: 1px solid #ddd;"><span style="background-color: #ffebe9; color: #cf222e; padding: 2px 6px; border-radius: 4px; font-size: 12px;">{item['metadata_category']}</span></td>
            <td style="padding: 10px; border: 1px solid #ddd;">{ref_link}</td>
            <td style="padding: 10px; border: 1px solid #ddd; font-size: 13px; color: #555;">{item['metadata_comment']}</td>
        </tr>
        """

    html = f"""
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #1f2937, #111827); color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">🚨 신규 활성 악성 확장 프로그램 감지 알림</h2>
            <p style="margin: 5px 0 0; opacity: 0.85; font-size: 14px;">크롬 웹 스토어에서 현재 설치 가능한 신규 의심 확장 프로그램이 발견되었습니다.</p>
        </div>
        <div style="border: 1px solid #e5e7eb; border-top: none; padding: 20px; border-radius: 0 0 8px 8px; background-color: #ffffff;">
            <p><strong>감지 일시:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')} (KST)</p>
            <p><strong>신규 발견 건수:</strong> <span style="font-size: 18px; color: #d9381e; font-weight: bold;">{len(new_items)}건</span></p>
            
            <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f3f4f6; text-align: left;">
                        <th style="padding: 10px; border: 1px solid #ddd;">확장 프로그램명</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">Extension ID</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">카테고리</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">분석 링크</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">코멘트</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
            
            <div style="margin-top: 25px; padding: 15px; background-color: #f9fafb; border-radius: 6px; font-size: 13px; color: #666;">
                📌 <strong>저장소 바로가기:</strong> <a href="https://github.com/NCITSSEC/malicious_browser_extensions_list" target="_blank">NCITSSEC/malicious_browser_extensions_list</a><br>
                본 메일은 GitHub Actions 자동 모니터링 시스템을 통해 발송되었습니다.
            </div>
        </div>
    </body>
    </html>
    """
    return html

def main():
    exclude_ids = load_exclude_ids()
    existing_ids = load_existing_ids()
    print(f"[*] 기존 등록되어 있던 확장 프로그램 수: {len(existing_ids)}개")
    
    rows = fetch_source_rows()
    print(f"[*] 원본 CSV 전체 행: {len(rows)}개")
    
    candidates = []
    seen_ids = set()
    
    for r in rows:
        name = (r.get('browser_extension') or '').strip()
        eid = (r.get('browser_extension_id') or '').strip().lower()
        cat = (r.get('metadata_category') or '').strip()
        
        # [제외 목록] 특정 제외 대상 ID 건너뛰기
        if eid in exclude_ids:
            continue
            
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
        
    print(f"[*] 조건 및 제외 필터링 후 후보군: {len(candidates)}개 (스토어 실시간 검증 대상)")
    
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
                
    print(f"[+] 최종 유효 데이터 수: {len(active_results)}개")
    
    # 신규 확장 프로그램 식별 (기존 목록에 없고 제외 대상도 아닌 신규)
    new_items = []
    if existing_ids:
        for item in active_results:
            if item['browser_extension_id'] not in existing_ids:
                new_items.append(item)
    print(f"[+] 신규 추가 감지된 확장 프로그램: {len(new_items)}개")
    
    # ID 기준으로 정렬
    active_results.sort(key=lambda x: x['browser_extension_id'])
    
    # CSV 저장 (UTF-8-BOM)
    with open(OUTPUT_CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=TARGET_COLUMNS)
        writer.writeheader()
        writer.writerows(active_results)
    print(f"[+] CSV 저장 완료: {OUTPUT_CSV_PATH}")
    
    # 신규 발견 건수가 있는 경우 HTML 리포트 생성
    if new_items:
        html_content = generate_email_html(new_items)
        with open(REPORT_HTML_PATH, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] 이메일 리포트 생성 완료: {REPORT_HTML_PATH}")
        
    # GitHub Actions 환경변수 출력 설정
    gh_output = os.environ.get('GITHUB_OUTPUT')
    if gh_output:
        try:
            with open(gh_output, 'a', encoding='utf-8') as f:
                f.write(f"has_new={'true' if new_items else 'false'}\n")
                f.write(f"new_count={len(new_items)}\n")
        except Exception:
            pass

if __name__ == "__main__":
    main()
