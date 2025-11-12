#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import pydeep
from pathlib import Path

# ===== 설정 =====
BASE_DIRS = [
    os.path.join(os.path.dirname(__file__), "win_8"),
    os.path.join(os.path.dirname(__file__), "win_10"),
    os.path.join(os.path.dirname(__file__), "win_11"),
]
OUT_FILE = Path(os.path.dirname(__file__)) / "win_code_pydeep.json"

def build_pydeep_db(base_dirs=BASE_DIRS, out_file=OUT_FILE):
    """모든 함수의 pydeep 해시만 리스트 형태로 저장"""
    hashes = []
    skipped = 0

    # 모든 jsonl 파일 수집
    all_files = []
    for base_dir in base_dirs:
        for root, _, files in os.walk(base_dir):
            for fn in files:
                if fn.endswith(".jsonl"):
                    all_files.append(os.path.join(root, fn))

    print(f"[*] 총 {len(all_files)}개 JSONL 파일 발견")

    # 각 파일 순회하며 해시 생성
    for idx, filepath in enumerate(all_files, start=1):
        fn = os.path.basename(filepath)
        print(f"[{idx}/{len(all_files)}] {fn} 처리 중...")

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    func = json.loads(line)
                except json.JSONDecodeError:
                    continue

                code = func.get("Source Code", "")
                if not code.strip():
                    skipped += 1
                    continue

                try:
                    h = pydeep.hash_buf(code.encode("utf-8"))
                    if isinstance(h, bytes):
                        h = h.decode("utf-8", errors="ignore").strip()

                    if h and "NULL" not in h and ":" in h:
                        hashes.append(h)
                    else:
                        skipped += 1
                except Exception as e:
                    skipped += 1
                    continue

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(hashes, f, ensure_ascii=False, indent=2)

    print(f"\n pydeep 해시 리스트 저장 완료: {out_file}")
    print(f"   총 {len(hashes)}개 저장, 스킵 {skipped}개 (짧거나 비어있는 코드)")

if __name__ == "__main__":
    build_pydeep_db()
