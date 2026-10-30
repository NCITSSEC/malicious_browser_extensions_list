import sys
import os
import io
import re
import csv
import ssl
import time
import json
import html as html_utils
from datetime import datetime, timezone, timedelta
from pathlib import Path
import urllib.request
import urllib.error
import concurrent.futures
from html.parser import HTMLParser
from urllib.parse import urlparse

# 콘솔 출력 UTF-8 인코딩 설정
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ctx = ssl.create_default_context()

SOURCE_CSV_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/Browser%20Extensions/browser_extensions_list.csv"
OUTPUT_CSV_PATH = "malicious_browser_extensions_list.csv"
REPORT_HTML_PATH = "new_extensions_report.html"
EXCLUDE_LIST_PATH = "exclude_list.txt"
STATE_PATH = "source_observations.json"

def observed_at():
    return datetime.now(timezone(timedelta(hours=9))).isoformat(timespec='seconds')

def load_state():
    if not os.path.exists(STATE_PATH):
        return None
    with open(STATE_PATH, encoding='utf-8') as f:
        state = json.load(f)
    if state.get('version') != 1 or not isinstance(state.get('ids'), dict):
        raise ValueError('관측 이력 형식 오류: 기존 파일을 확인하세요.')
    for eid, entry in state['ids'].items():
        if not isinstance(entry, dict) or not isinstance(entry.get('baseline'), bool) or not isinstance(entry.get('notified'), bool) or not isinstance(entry.get('first_seen'), str):
            raise ValueError(f'관측 이력 항목 오류: {eid}')
    return state

def update_observations(rows, state, existing_ids, now):
    # 필터 적용 전 원본 전체 ID를 보관해야 기존의 비활성 항목을 신규로 오인하지 않는다.
    initializing = state is None
    if initializing:
        state = {'version': 1, 'baseline_at': now, 'ids': {}}
    ids = {(r.get('browser_extension_id') or '').strip().lower() for r in rows}
    ids.update(existing_ids)
    for eid in sorted(ids - {''}):
        state['ids'].setdefault(eid, {
            'first_seen': now, 'baseline': initializing or eid in existing_ids,
            'notified': eid in existing_ids,
        })
    return state, initializing

def select_new_items(active_results, state, now):
    items = []
    for item in sorted(active_results, key=lambda x: x['browser_extension_id']):
        entry = state['ids'][item['browser_extension_id']]
        if not entry['baseline'] and not entry['notified']:
            items.append(item)
            entry['notified'] = True
            entry['qualified_at'] = now
    return items

def atomic_write(path, content, encoding='utf-8'):
    temporary = Path(str(path) + '.tmp')
    with temporary.open('w', encoding=encoding, newline='') as f:
        f.write(content)
    os.replace(temporary, path)

def acknowledge_notifications():
    state = load_state()
    if state is None:
        raise RuntimeError('메일 확인 처리에 필요한 관측 이력이 없습니다.')
    for entry in state.get('pending_notifications', {}).values():
        state['ids'][entry['browser_extension_id']]['emailed_at'] = observed_at()
    state['pending_notifications'] = {}
    atomic_write(STATE_PATH, json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    print('[+] 발송 완료한 알림 대기열을 비웠습니다.')

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
            if not set(TARGET_COLUMNS).issubset(reader.fieldnames or []):
                raise ValueError('기존 CSV 필수 컬럼이 없습니다.')
            return set(r['browser_extension_id'].strip().lower() for r in reader if r.get('browser_extension_id'))
    except Exception as exc:
        raise RuntimeError('기존 CSV를 읽지 못했습니다. 갱신을 중단합니다.') from exc

def fetch_source_rows():
    print(f"[*] 원본 CSV 다운로드 중: {SOURCE_CSV_URL}")
    req = urllib.request.Request(SOURCE_CSV_URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        content = resp.read().decode('utf-8-sig')
    reader = csv.DictReader(io.StringIO(content))
    if not set(TARGET_COLUMNS).issubset(reader.fieldnames or []):
        raise ValueError('원본 CSV 필수 컬럼이 없습니다.')
    rows = list(reader)
    if not rows:
        raise ValueError('원본 CSV가 비어 있습니다.')
    return rows

class StorePage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.canonical = ''
        self.text = []
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('script', 'style'):
            self.hidden_depth += 1
        if tag == 'link' and 'canonical' in attrs.get('rel', '').split():
            self.canonical = attrs.get('href', '')

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth:
            self.text.append(data)

def store_page_active(body, ext_id):
    page = StorePage()
    page.feed(body)
    text = ' '.join(' '.join(page.text).split()).lower()
    if any(marker in text for marker in (
        'this item is not available', 'this item is no longer available',
        'this extension is no longer available', 'item not found',
    )):
        return False
    canonical = urlparse(page.canonical)
    matches_id = re.fullmatch(r'/detail/(?:[^/]+/)?' + re.escape(ext_id) + r'/?', canonical.path)
    if canonical.scheme == 'https' and canonical.hostname == 'chromewebstore.google.com' and matches_id and 'add to chrome' in text:
        return True
    # CWS는 존재하지 않거나 접근 불가한 항목도 HTTP 200의 빈 화면으로 응답한다.
    # 상세 데이터(ds:0)의 명시적인 오류 상태를 확인하며, 빈 화면만으로는 제외하지 않는다.
    status = re.search(
        r'''AF_initDataCallback\(\{\s*key:\s*['"]ds:0['"]\s*,\s*data:\s*\[\s*(\d+)\s*\]\s*,\s*errorHasStatus:\s*true''',
        body,
    )
    if not page.canonical and status:
        code = int(status.group(1))
        if code in (5, 7):  # NOT_FOUND / PERMISSION_DENIED: 현재 요청에서 설치 불가
            return False
        raise ValueError(f'스토어 상세 데이터 오류 상태: {code} (비활성으로 확정하지 않음)')
    raise ValueError('대상 ID의 스토어 상세 페이지와 Add to Chrome 표시를 확인할 수 없습니다.')

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
    last_error = None
    for _ in range(max_retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                if store_page_active(body, ext_id):
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
            last_error = e
            if e.code == 404:
                return None
            time.sleep(1)
        except Exception as e:
            last_error = e
            time.sleep(0.5)
            
    raise RuntimeError(f'스토어 상태 확인 실패: {ext_id}: {type(last_error).__name__}: {last_error}') from last_error

def generate_email_html(new_items):
    """
    신규 발견된 악성 확장 프로그램에 대한 깔끔한 HTML 메일 본문 생성
    """
    rows_html = ""
    for original in new_items:
        item = {key: html_utils.escape(str(value), quote=True) for key, value in original.items()}
        store_url = f"https://chromewebstore.google.com/detail/{item['browser_extension_id']}"
        ref_link = f"<a href='{item['metadata_link']}' target='_blank'>링크</a>" if original['metadata_link'].startswith(('https://', 'http://')) else "-"
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
            <p><strong>감지 일시:</strong> {observed_at()} (KST)</p>
            <p>기준선 이후 원본에서 처음 관측했으며 수집 조건을 통과한 ID입니다. 원본 등록일이나 악성 행위 시작일을 뜻하지 않습니다.</p>
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
    now = observed_at()
    state, initializing = update_observations(rows, load_state(), existing_ids, now)
    if initializing:
        print('[*] 최초 실행: 원본 전체 ID를 기준선으로 등록합니다. 기존 항목은 신규 알림에서 제외합니다.')
    
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
        if cat_upper in ('PROXY', 'VPN', 'PROXY/VPN') or 'PROXY/VPN' or 'password manager' or 'cryptocurrency' in cat_upper:
            continue
            
        if eid in seen_ids:
            continue
            
        seen_ids.add(eid)
        candidates.append(r)
        
    print(f"[*] 조건 및 제외 필터링 후 후보군: {len(candidates)}개 (스토어 실시간 검증 대상)")
    
    # [조건 1] 크롬 웹 스토어 설치 가능 여부 실시간 병렬 검증
    active_results = []
    failed_checks = []
    start_time = time.time()
    total = len(candidates)
    completed = 0
    
    print(f"[*] 크롬 웹 스토어 실시간 검증 시작 (15 동시 스레드)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_row = {executor.submit(check_webstore_active, row): row for row in candidates}
        for future in concurrent.futures.as_completed(future_to_row):
            completed += 1
            try:
                res = future.result()
            except Exception as exc:
                failed_checks.append(str(exc))
                res = None
            if res:
                active_results.append(res)
            if completed % 100 == 0 or completed == total:
                elapsed = time.time() - start_time
                print(f"    - 진행률: {completed}/{total} 완료 ({len(active_results)}개 활성 확인됨) [{elapsed:.1f}초]")

    if failed_checks:
        for error in failed_checks[:10]:
            print(f'[!] {error}')
        raise RuntimeError(f'{len(failed_checks)}개 스토어 상태 확인 실패: CSV 및 관측 이력 갱신을 중단합니다.')
                
    print(f"[+] 최종 유효 데이터 수: {len(active_results)}개")
    
    # 신규 확장 프로그램 식별 (기존 목록에 없고 제외 대상도 아닌 신규)
    new_items = select_new_items(active_results, state, now)
    pending = state.setdefault('pending_notifications', {})
    for item in new_items:
        pending[item['browser_extension_id']] = item
    # 이전 실행에서 SMTP 발송에 실패한 항목도 재시도한다.
    new_items = [pending[eid] for eid in sorted(pending)]
    html_content = generate_email_html(new_items) if new_items else None
    print(f"[+] 신규 추가 감지된 확장 프로그램: {len(new_items)}개")
    
    # ID 기준으로 정렬
    active_results.sort(key=lambda x: x['browser_extension_id'])
    
    # CSV 저장 (UTF-8-BOM)
    buffer = io.StringIO(newline='')
    writer = csv.DictWriter(buffer, fieldnames=TARGET_COLUMNS)
    writer.writeheader()
    writer.writerows(active_results)
    atomic_write(OUTPUT_CSV_PATH, buffer.getvalue(), 'utf-8-sig')
    atomic_write(STATE_PATH, json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    print(f"[+] CSV 저장 완료: {OUTPUT_CSV_PATH}")
    
    # 신규 발견 건수가 있는 경우 HTML 리포트 생성
    if new_items:
        atomic_write(REPORT_HTML_PATH, html_content)
        print(f"[+] 이메일 리포트 생성 완료: {REPORT_HTML_PATH}")
    else:
        Path(REPORT_HTML_PATH).unlink(missing_ok=True)
        
    # GitHub Actions 환경변수 출력 설정
    gh_output = os.environ.get('GITHUB_OUTPUT')
    if gh_output:
        with open(gh_output, 'a', encoding='utf-8') as f:
            f.write(f"has_new={'true' if new_items else 'false'}\n")
            f.write(f"new_count={len(new_items)}\n")
            f.write(f"active_count={len(active_results)}\n")
            f.write(f"source_count={len(rows)}\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--ack-notifications', action='store_true', help='SMTP 발송 성공 후에만 알림 대기열을 비웁니다.')
    args = parser.parse_args()
    if args.ack_notifications:
        acknowledge_notifications()
    else:
        main()
