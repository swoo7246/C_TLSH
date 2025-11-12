import json
import os
from pathlib import Path

# 입력 / 출력 디렉터리
INPUT_DIR = Path("result")
OUTPUT_DIR = Path("sim80_result")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 유사도 기준
THRESHOLD = 0.8

# result 디렉토리 내 모든 .json 파일 처리
for file_path in INPUT_DIR.glob("*.json"):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        filtered = {}
        for func_name, entries in data.items():
            filtered_entries = [e for e in entries if e.get("Similarity", 0) >= THRESHOLD]
            if filtered_entries:
                filtered[func_name] = filtered_entries

        output_path = OUTPUT_DIR / file_path.name
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(filtered, f, indent=4, ensure_ascii=False)

        print(f"[+] {file_path.name} → {output_path} (필터링 완료)")

    except Exception as e:
        print(f"[!] {file_path.name} 처리 중 오류 발생: {e}")

print(f"\n=== 모든 파일 처리 완료 ===\n입력: {INPUT_DIR}\n출력: {OUTPUT_DIR}")
