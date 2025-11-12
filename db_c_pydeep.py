#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pydeep
import time
from pathlib import Path
from tqdm import tqdm
from multiprocessing.dummy import Pool  # Thread 기반 Pool (DB 공유)

# ===== 경로 설정 =====
DB_PATH = Path("win_code_pydeep.json")   # pydeep 해시 리스트 DB
SAMPLE_DIR = Path("sample")              # 비교할 함수 jsonl 폴더
OUTPUT_DIR = Path("sample_diff_win_pydeep_threaded")  # 결과 저장 폴더
ERROR_LOG = OUTPUT_DIR / "error.txt"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ===== 설정 =====
THREADS = 10  # 사용할 스레드 개수

# ===== pydeep 유효성 검사 함수 =====
def is_valid_pydeep(h):
    if not h:
        return False
    if isinstance(h, bytes):
        try:
            h = h.decode("utf-8", errors="ignore").strip()
        except Exception:
            return False
    if "NULL" in h or len(h) < 10:
        return False
    if h.count(":") < 2:
        return False
    parts = h.split(":")
    if not parts[0].isdigit():
        return False
    return True

# ===== DB 전체 로드 (1회만) =====
print(f"[i] Loading DB from {DB_PATH} ...")
with open(DB_PATH, "r", encoding="utf-8") as f:
    db_hashes = json.load(f)
db_hashes = [h for h in db_hashes if is_valid_pydeep(h)]
print(f"[i] 유효한 DB 해시 개수: {len(db_hashes):,}개\n")

# ===== 함수 비교 로직 =====
def process_function(entry):
    try:
        func_name = entry.get("Function Name")
        code = entry.get("Source Code", "")
        if not func_name or not code.strip():
            return None

        start_time = time.time()

        # pydeep 해시 계산
        h = pydeep.hash_buf(code.encode("utf-8"))
        if isinstance(h, bytes):
            h = h.decode("utf-8", errors="ignore").strip()
        if not is_valid_pydeep(h):
            return None

        # DB 전수 비교
        min_diff = 999
        for db_hash in db_hashes:
            try:
                sim = pydeep.compare(h, db_hash)
                if 0 <= sim <= 100:
                    diff = 100 - sim
                    if diff < min_diff:
                        min_diff = diff
                        if min_diff == 0:
                            break
            except Exception:
                continue

        elapsed = time.time() - start_time
        print(f"[+] {func_name} (min_diff={min_diff:.1f}) | {elapsed:.2f}s")

        return {"Function Name": func_name, "min_diff": min_diff}

    except Exception:
        return None

# ===== error.txt 초기화 =====
with open(ERROR_LOG, "w", encoding="utf-8") as ferr:
    ferr.write("### Functions that failed to save ###\n")

# ===== sample 디렉토리 처리 =====
print(f"[i] Thread Pool 시작 ({THREADS} threads, DB 공유)\n")

for jsonl_file in tqdm(sorted(SAMPLE_DIR.glob("*.jsonl")), desc="Processing sample"):
    output_path = OUTPUT_DIR / jsonl_file.name

    # 이미 처리된 함수 스킵
    existing_funcs = set()
    if output_path.exists():
        with open(output_path, "r", encoding="utf-8") as f_existing:
            for line in f_existing:
                try:
                    entry = json.loads(line.strip())
                    fn = entry.get("Function Name")
                    if fn:
                        existing_funcs.add(fn)
                except json.JSONDecodeError:
                    continue

    # JSONL 입력 읽기
    entries = []
    with open(jsonl_file, "r", encoding="utf-8") as f_in:
        for line in f_in:
            try:
                entry = json.loads(line.strip())
                if entry.get("Function Name") not in existing_funcs:
                    entries.append(entry)
            except json.JSONDecodeError:
                continue

    if not entries:
        print(f"[!] {jsonl_file.name} :: 처리할 함수 없음 (skip)")
        continue

    # Thread Pool 실행 — 결과를 즉시 파일에 기록
    with open(output_path, "a", encoding="utf-8") as f_out, \
         open(ERROR_LOG, "a", encoding="utf-8") as ferr, \
         Pool(THREADS) as pool:

        for res in tqdm(pool.imap_unordered(process_function, entries),
                        total=len(entries),
                        desc=f"{jsonl_file.name}"):
            if res:
                # 결과 즉시 파일에 한 줄씩 저장
                json.dump(res, f_out, ensure_ascii=False)
                f_out.write("\n")
                f_out.flush()
            else:
                # 실패한 경우 로그
                ferr.write(f"{jsonl_file.name} :: 처리 실패\n")

print(f"\n모든 파일 처리 완료! 결과 디렉토리: {OUTPUT_DIR}")
print(f"저장 실패 함수 목록: {ERROR_LOG}")
