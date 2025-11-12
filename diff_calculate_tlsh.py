#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import tlsh
from pathlib import Path
from tqdm import tqdm

# ===== 경로 설정 =====
DB_PATH = Path("dike_code_hash.json")
SAMPLE_DIR = Path("sample")
OUTPUT_DIR = Path("sample_diff_dike")
ERROR_LOG = OUTPUT_DIR / "error.txt"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ===== TLSH 유효성 검사 함수 =====
def is_valid_tlsh(h):
    return isinstance(h, str) and h.startswith("T") and len(h) > 20 and "NULL" not in h

# ===== 데이터베이스 로드 =====
with open(DB_PATH, "r", encoding="utf-8") as f:
    db = json.load(f)

db_hashes = [d["hash"] for d in db if is_valid_tlsh(d.get("hash"))]
print(f"[i] 유효한 DB 해시 개수: {len(db_hashes)}개")

# ===== error.txt 초기화 =====
with open(ERROR_LOG, "w", encoding="utf-8") as ferr:
    ferr.write("### Functions that failed to save ###\n")

# ===== sample 디렉토리 내 모든 jsonl 파일 처리 =====
for jsonl_file in tqdm(sorted(SAMPLE_DIR.glob("*.jsonl")), desc="Processing sample"):
    output_path = OUTPUT_DIR / jsonl_file.name

    # 이미 존재하는 결과 파일이면 기존 함수 목록 불러오기
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
        print(f"[→] {output_path.name} 존재함. 이미 처리된 함수 {len(existing_funcs)}개 스킵 예정")

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

                try:
                    h = tlsh.hash(code.encode("utf-8"))
                    if not is_valid_tlsh(h):
                        raise ValueError("Invalid TLSH hash")

                    # 최소 diff 계산
                    min_diff = float("inf")
                    for db_hash in db_hashes:
                        try:
                            diff = tlsh.diff(h, db_hash)
                            if diff < min_diff:
                                min_diff = diff
                        except Exception:
                            continue

                    # 결과 저장
                    json.dump({"Function Name": func_name, "min_diff": min_diff},
                              f_out, ensure_ascii=False)
                    f_out.write("\n")
                    f_out.flush()

                    print(f"[+] {jsonl_file.name} :: {func_name} (min_diff={min_diff:.1f}) 추가됨")

                except Exception as e:
                    # 함수 저장 실패만 error.txt에 기록
                    ferr.write(f"{jsonl_file.name} :: {func_name} - {str(e)}\n")
                    print(f"[x] {jsonl_file.name} :: {func_name} 저장 실패 ({e})")
                    continue

            except json.JSONDecodeError:
                continue

    print(f"[✓] {jsonl_file.name} → {output_path.name} 처리 완료")

print(f"\n 모든 파일 처리 완료! 결과 디렉토리: {OUTPUT_DIR}")
print(f" 저장 실패 함수 목록: {ERROR_LOG}")
