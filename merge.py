#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json

DIR_DIKE = "sample_diff_dike"
DIR_WIN  = "sample_diff_win"
DIR_OUT  = "sample_diff_all"

os.makedirs(DIR_OUT, exist_ok=True)

def read_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def merge_by_line(path_a, path_b, out_path):
    lines_a = read_lines(path_a)
    lines_b = read_lines(path_b)
    n = min(len(lines_a), len(lines_b))

    if len(lines_a) != len(lines_b):
        print(f"[WARN] {os.path.basename(path_a)} line mismatch: {len(lines_a)} vs {len(lines_b)}")

    merged = []
    for i in range(n):
        try:
            obj_a = json.loads(lines_a[i])
            obj_b = json.loads(lines_b[i])
        except json.JSONDecodeError as e:
            print(f"[WARN] JSON parse error at line {i+1}: {e}")
            continue

        name_a = obj_a.get("Function Name") or obj_a.get("func_id") or obj_a.get("name")
        name_b = obj_b.get("Function Name") or obj_b.get("func_id") or obj_b.get("name")

        if not name_a or not name_b:
            continue

        name_a = name_a.strip().replace("\r", "").replace("\x00", "")
        name_b = name_b.strip().replace("\r", "").replace("\x00", "")

        if name_a != name_b:
            print(f"[SKIP] {os.path.basename(path_a)} line {i+1}: name mismatch '{name_a}' vs '{name_b}'")
            continue

        diff_a = obj_a.get("min_diff", float("inf"))
        diff_b = obj_b.get("min_diff", float("inf"))
        chosen = obj_a if diff_a <= diff_b else obj_b
        merged.append(chosen)

    with open(out_path, "w", encoding="utf-8") as f:
        for obj in merged:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"[OK] merged {os.path.basename(out_path)} ({len(merged)} funcs)")

files = sorted(f for f in os.listdir(DIR_DIKE) if f.endswith(".jsonl"))

for fname in files:
    path_dike = os.path.join(DIR_DIKE, fname)
    path_win  = os.path.join(DIR_WIN, fname)
    path_out  = os.path.join(DIR_OUT, fname)

    if not os.path.exists(path_win):
        print(f"[SKIP] {fname}: {DIR_WIN}에 해당 파일 없음")
        continue

    merge_by_line(path_dike, path_win, path_out)

print("모든 파일 병합 완료!")
