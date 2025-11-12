#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
from pathlib import Path
import pandas as pd
from tqdm import tqdm

# ───────────────────────────────────────────────────────────────
# 기존 헬퍼 함수들 (변경 없음)
# ───────────────────────────────────────────────────────────────

def is_halt_only(src: str) -> bool:
    lines = src.splitlines()
    body_started = False
    body_lines = []
    for line in lines:
        if not body_started:
            if "{" in line:
                body_started = True
            continue
        if "}" in line:
            break
        stripped = line.strip()
        if stripped:
            body_lines.append(stripped)
    return (len(body_lines) == 1 and body_lines[0] == "halt_baddata();")

def extract_function_name(source: str) -> str:
    first_line = source.strip().split('\n', 1)[0]
    m = re.search(r'\b([A-Za-z_]\w*)\s*\(', first_line)
    return m.group(1) if m else ''

def is_self_trivial_wrapper(func_name: str, source: str) -> bool:
    m = re.search(r'\{([\s\S]*?)\}', source)
    if not m:
        return False
    lines = [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]

    call_only    = re.compile(rf'^{re.escape(func_name)}\s*\(.*\)\s*;\s*$')
    return_call  = re.compile(rf'^return\s+{re.escape(func_name)}\s*\(.*\)\s*;\s*$')

    if len(lines) == 1 and (call_only.match(lines[0]) or return_call.match(lines[0])):
        return True
    if len(lines) == 2:
        if call_only.match(lines[0]) and lines[1] == 'return;':
            return True
        if return_call.match(lines[0]) and lines[1] == 'return;':
            return True
    return False

def apply_filters(row):
    fname = row["Function Name"]
    src   = row["Source Code"]
    if "<EXTERNAL>" in fname:
        return True
    if is_halt_only(src):
        return True
    func_head_name = extract_function_name(src) or fname
    if is_self_trivial_wrapper(func_head_name, src):
        return True
    return True

# ───────────────────────────────────────────────────────────────
# 전처리 및 파싱
# ───────────────────────────────────────────────────────────────

RE_BLOCK_COMMENTS = re.compile(r'/\*.*?\*/', flags=re.DOTALL)

def preprocess_text(raw: str) -> str:
    txt = RE_BLOCK_COMMENTS.sub('', raw)
    txt = re.sub(r'Parameter:.*\n', '', txt)
    txt = re.sub(r'Called by:.*\n', '', txt)
    txt = re.sub(r'\n+', '\n', txt)
    return txt

def parse_ghidra_txt(cleaned_text: str):
    function_names, addresses, source_codes = [], [], []
    lines = cleaned_text.splitlines()
    current_function_name = None
    current_source_code = []
    capturing_code = False

    for line in lines:
        if "Function Found:" in line:
            if current_function_name is not None:
                source_codes.append("\n".join(current_source_code).strip())
                current_source_code = []
                capturing_code = False
            current_function_name = line.split(":", 1)[1].strip()
            function_names.append(current_function_name)

        elif "Address:" in line:
            addresses.append(line.split(":", 1)[1].strip())

        elif "Decompiled C Code:" in line:
            capturing_code = True

        elif capturing_code:
            current_source_code.append(line.strip())

    if current_function_name is not None:
        source_codes.append("\n".join(current_source_code).strip())

    n = min(len(function_names), len(addresses), len(source_codes))
    return function_names[:n], addresses[:n], source_codes[:n]

def process_single_file(in_path: Path, out_path: Path) -> int:
    raw = in_path.read_text(encoding='utf-8', errors='ignore')
    cleaned = preprocess_text(raw)
    fnames, addrs, codes = parse_ghidra_txt(cleaned)

    if not fnames:
        return 0

    df = pd.DataFrame({
        "Function Name": fnames,
        "Address": addrs,
        "Source Code": codes
    })
    df = df[df.apply(apply_filters, axis=1)].reset_index(drop=True)
    if df.empty:
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_json(out_path, orient="records", lines=True, force_ascii=False)
    return len(df)

# ───────────────────────────────────────────────────────────────
# 메인
# ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Ghidra TXT 일괄 전처리 → JSONL 저장 (진행 상황 출력)"
    )
    parser.add_argument("--input_dir",  type=str, required=True,
                        help="입력 TXT 폴더 (재귀 검색 기본).")
    parser.add_argument("--output_dir", type=str, required=True,
                        help="출력 JSONL 폴더.")
    parser.add_argument("--no_recursive", action="store_true",
                        help="재귀 검색하지 않음.")

    args = parser.parse_args()
    in_dir = Path(args.input_dir).resolve()
    out_dir = Path(args.output_dir).resolve()

    pattern_iter = in_dir.rglob("*.txt") if not args.no_recursive else in_dir.glob("*.txt")
    txt_files = sorted([p for p in pattern_iter if p.is_file()])

    if not txt_files:
        print(f"[!] TXT 파일이 없습니다: {in_dir}")
        return

    total_saved = 0
    with tqdm(total=len(txt_files), desc="Processing files", unit="file") as pbar:
        for txt in txt_files:
            rel = txt.relative_to(in_dir)
            out_path = (out_dir / rel).with_suffix(".jsonl")
            try:
                saved = process_single_file(txt, out_path)
                if saved > 0:
                    tqdm.write(f"[?] {txt.name} → {out_path.name} (records={saved})")
                    total_saved += saved
                else:
                    tqdm.write(f"[-] {txt.name} → 필터 후 비어 있음")
            except Exception as e:
                tqdm.write(f"[!] {txt.name} 처리 오류: {e}")
            pbar.update(1)

    print(f"\n[완료] 총 {len(txt_files)}개 파일 처리, {total_saved}개 함수 저장")

if __name__ == "__main__":
    main()
