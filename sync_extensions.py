import os
import pandas as pd
import requests

# 원본 및 타겟 설정
SOURCE_RAW_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/Browser%20Extensions/browser_extensions_list.csv"
TARGET_FILE = "browser_extensions_list.csv"
COLUMNS = ['browser_extension', 'browser_extension_id', 'metadata_link', 'metadata_comment']

def sync_data():
    print("1. 원본 CSV 다운로드 중...")
    # 원본 다운로드 및 지정된 컬럼만 로드
    df_source = pd.read_csv(SOURCE_RAW_URL, usecols=lambda c: c.strip() in COLUMNS)
    
    # 공백 제거 및 컬럼 순서 정렬
    df_source.columns = df_source.columns.str.strip()
    df_source = df_source[COLUMNS].dropna(subset=['browser_extension_id'])
    # 앞뒤 공백 및 문자열 정리
    df_source = df_source.astype(str).map(lambda x: x.strip())
    
    # 2. 내 저장소의 기존 파일 확인
    if os.path.exists(TARGET_FILE):
        print("2. 기존 CSV 확인 및 차분 병합 중...")
        df_target = pd.read_csv(TARGET_FILE, dtype=str).fillna("")
        df_target = df_target[COLUMNS].map(lambda x: x.strip())
        
        # 합친 후 고유 식별자(browser_extension_id) 기준 중복 제거 (또는 전체 행 기준)
        # 만약 id 하나에 여러 메타데이터가 있을 수 있다면 전체 행 중복 제거: subset=None
        initial_len = len(df_target)
        df_combined = pd.concat([df_target, df_source], ignore_index=True)
        
        # 전체 4개 컬럼이 완전히 일치하는 행 제거 (신규 데이터만 유지)
        df_combined = df_combined.drop_duplicates(subset=COLUMNS, keep='first')
        
        new_count = len(df_combined) - initial_len
        print(f"-> 신규 추가된 행 개수: {new_count}건")
        
        if new_count == 0:
            print("변경된 데이터가 없습니다. 커밋을 건너뜁니다.")
            return False
            
        df_result = df_combined
    else:
        print("2. 최초 생성: 원본 데이터를 타겟 파일로 생성합니다.")
        df_result = df_source.drop_duplicates(subset=COLUMNS)
    
    # 3. CSV 파일 저장
    df_result.to_csv(TARGET_FILE, index=False, encoding='utf-8')
    print("3. 저장 완료!")
    return True

if __name__ == "__main__":
    has_changes = sync_data()
    # GitHub Actions 환경변수에 변경 여부 전달
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"has_changes={'true' if has_changes else 'false'}\n")
