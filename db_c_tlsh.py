import os
import json
import tlsh

BASE_DIRS = [
    os.path.join(os.path.dirname(__file__), "dike_c"),
]
WIN_HASH_DB = os.path.join(os.path.dirname(__file__), "dike_code_hash.json")


def build_windows_hash_db(base_dirs=BASE_DIRS, out_file=WIN_HASH_DB):
    """여러 함수 폴더에서 TLSH 해시 DB 생성"""
    hashes = []
    skipped = 0

    # 1. 먼저 전체 jsonl 파일 개수 세기
    all_files = []
    for base_dir in base_dirs:
        for root, _, files in os.walk(base_dir):
            for fn in files:
                if fn.endswith(".jsonl"):
                    all_files.append(os.path.join(root, fn))

    total_files = len(all_files)
    print(f"[*] 총 {total_files}개 .jsonl 파일 발견")

    # 2. 순회하면서 진행률 출력
    for idx, filepath in enumerate(all_files, start=1):
        fn = os.path.basename(filepath)
        print(f"[{idx}/{total_files}] {fn} 처리 중... ({idx/total_files*100:.2f}%)")

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

                # TLSH는 최소 50바이트 이상 + 충분한 랜덤성 필요
                h = tlsh.hash(code.encode("utf-8"))
                if h and not h.startswith("TNULL"):
                    hashes.append({
                        "hash": h,
                        "function": func.get("Function Name"),
                        "address": func.get("Address"),
                        "file": fn,
                    })
                else:
                    skipped += 1

    # 3. 결과 저장
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(hashes, f, ensure_ascii=False, indent=2)

    print(f"\nTLSH DB 생성 완료: {out_file}")
    print(f"    총 해시 {len(hashes)}개 저장, 스킵 {skipped}개 (짧거나 단순한 코드)")
    return hashes


if __name__ == "__main__":
    build_windows_hash_db()
