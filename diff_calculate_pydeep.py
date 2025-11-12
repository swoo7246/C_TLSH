#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pydeep
from pathlib import Path
from tqdm import tqdm

# ===== 경로 설정 =====
DB_PATH = Path("win_code_pydeep.json")   # pydeep 해시 리스트 DB
SAMPLE_DIR = Path("sample")              # 비교할 함수 jsonl 폴더
OUTPUT_DIR = Path("sample_diff_win_pydeep")  # 결과 저장 폴더
ERROR_LOG = OUTPUT_DIR / "error.txt"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ===== 설정 =====
CHUNKS = 10  # DB를 10개 리스트로 분할

# ===== pydeep 유효성 검사 함수 =====
def is_valid_pydeep(h):
    """pydeep 해시 문자열 유효성 검사"""
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

# ===== DB 한 번에 로드 후 10개로 분할 =====
print(f"[i] Loading DB from {DB_PATH} ...")
with open(DB_PATH, "r", encoding="utf-8") as f:
    db_hashes = json.load(f)

# 유효한 해시만 남기기
db_hashes = [h for h in db_hashes if is_valid_pydeep(h)]
print(f"[i] 유효한 DB 해시 개수: {len(db_hashes)}개")

# 10개로 분할
chunk_size = len(db_hashes) // CHUNKS
db_chunks = []
for i in range(CHUNKS):
    start = i * chunk_size
    end = (i + 1) * chunk_size if i < CHUNKS - 1 else len(db_hashes)
    db_chunks.append(db_hashes[start:end])
print(f"[i] DB를 {CHUNKS}개로 분할 완료\n")

# ===== error.txt 초기화 =====
with open(ERROR_LOG, "w", encoding="utf-8") as ferr:
    ferr.write("### Functions that failed to save ###\n")

# ===== sample 디렉토리 처리 =====
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

    with open(jsonl_file, "r", encoding="utf-8") as f_in, \
         open(output_path, "a", encoding="utf-8") as f_out, \
         open(ERROR_LOG, "a", encoding="utf-8") as ferr:

        for line in f_in:
            try:
                entry = json.loads(line.strip())
                func_name = entry.get("Function Name")
                code = entry.get("Source Code", "")

                if not func_name or func_name in existing_funcs:
                    continue
                if not code.strip():
                    continue

                # pydeep 해시 계산
                h = pydeep.hash_buf(code.encode("utf-8"))
                if isinstance(h, bytes):
                    h = h.decode("utf-8", errors="ignore").strip()
                if not is_valid_pydeep(h):
                    raise ValueError("Invalid pydeep hash")

                # 최소 diff 계산
                min_diff = 999
                for chunk in db_chunks:
                    for db_hash in chunk:
                        try:
                            sim = pydeep.compare(h, db_hash)
                            if sim < 0 or sim > 100:
                                continue
                            diff = 100 - sim
                            if diff < min_diff:
                                min_diff = diff
                                if min_diff == 0:
                                    break
                        except Exception:
                            continue
                    if min_diff == 0:
                        break

                # 결과 저장
                json.dump({"Function Name": func_name, "min_diff": min_diff},
                          f_out, ensure_ascii=False)
                f_out.write("\n")
                f_out.flush()

                print(f"[+] {jsonl_file.name} :: {func_name} (min_diff={min_diff:.1f})")

            except Exception as e:
                ferr.write(f"{jsonl_file.name} :: {str(e)}\n")
                continue

print(f"\n모든 파일 처리 완료! 결과 디렉토리: {OUTPUT_DIR}")
print(f"저장 실패 함수 목록: {ERROR_LOG}")
