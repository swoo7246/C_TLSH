#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, json
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

# ===== 경로 설정 =====
FUNC_DIR = Path("functions")
DIFF_DIR = Path("sample_diff_win_pydeep")
GT_DIR = Path("f")
OUT_DIR = Path("win_c_pydeep_result")  # 그래프 및 텍스트 저장 폴더
OUT_DIR.mkdir(exist_ok=True)

# ===== 악성코드 이름 및 매핑 =====
MALWARES = {
    "AbbadonRAT": "74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7",
    "Baduk": "8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9",
    "BPFDoor": "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7",
    "Emotet": "76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21",
    "Emotet2": "249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db",
    "IISerpent": "aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47",
    "RaccoonStealer": "0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909",
}

# ===== 파라미터 =====
DIFF_THRESHOLDS = list(range(0, 201, 1))

# ===== Precision, Recall 계산 함수 =====
def compute_metrics(tp, fp, fn):
    prec = tp / (tp + fp) if tp + fp > 0 else 0
    recall = tp / (tp + fn) if tp + fn > 0 else 0
    f1 = 2 * prec * recall / (prec + recall) if prec + recall > 0 else 0
    return prec, recall, f1

# ===== 메인 =====
for malware, sha in MALWARES.items():
    print(f"\n=== {malware} ===")

    gt_path = GT_DIR / f"{malware}.json"
    diff_path = DIFF_DIR / f"{sha}.jsonl"
    func_path = FUNC_DIR / f"{sha}.filtered_funcs.json"

    if not (gt_path.exists() and diff_path.exists() and func_path.exists()):
        print(f"[!] {malware}: 필요한 파일 누락 (건너뜀)")
        continue

    # --- Ground Truth --- 
    gt_funcs = set(json.load(open(gt_path, encoding="utf-8")).keys())

    # --- Diff 데이터 --- 
    diff_data = []
    with open(diff_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                diff_data.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    diff_map = {d["Function Name"]: d["min_diff"] for d in diff_data}

    # --- Functions 리스트 --- 
    func_data = json.load(open(func_path, encoding="utf-8"))
    all_functions = set(func_data["functions"])
    total_funcs_count = len(all_functions)
    gt_count = len(gt_funcs)

    precisions, recalls, f1s = [], [], []
    excluded_counts = []  # 제거된 함수 수 리스트 추가

    # --- 결과 저장 파일 준비 --- 
    txt_path = OUT_DIR / f"{malware}_metrics_func.txt"
    with open(txt_path, "w", encoding="utf-8") as ftxt:
        ftxt.write(f"=== {malware} ===\n")
        ftxt.write(f"Ground-truth 함수 수 (malware.json): {gt_count}\n\n")
        ftxt.write(f"{'Diff':>5} | {'Precision':>9} | {'Recall':>7} | {'F1':>7} | {'RemovedCnt':>11} | Excluded Functions\n")
        ftxt.write("-" * 160 + "\n")

        # --- Diff threshold 루프 --- 
        for dth in DIFF_THRESHOLDS:
            benign_funcs = {f for f, diff in diff_map.items() if diff < dth}
            remaining_funcs = all_functions - benign_funcs
            gt_valid = gt_funcs

            tp = len(remaining_funcs & gt_valid)
            fp = len(remaining_funcs - gt_valid)
            fn = len(gt_valid - remaining_funcs)

            prec, recall, f1 = compute_metrics(tp, fp, fn)
            precisions.append(prec)
            recalls.append(recall)
            f1s.append(f1)

            excluded_cnt = len(benign_funcs)
            excluded_counts.append(excluded_cnt)

            excluded_str = ", ".join(sorted(benign_funcs)) if excluded_cnt > 0 else "(없음)"
            ftxt.write(f"{dth:5d} | {prec:9.5f} | {recall:7.5f} | {f1:7.5f} | {excluded_cnt:11d} | {excluded_str}\n")

    print(f"[+] {malware} metrics 저장 완료 → {txt_path}")

    # --- Best threshold --- 
    best_idx = 0
    for i in range(1, len(DIFF_THRESHOLDS)):
        if recalls[i] < recalls[i - 1]:
            best_idx = i - 1
            break
        if i == len(DIFF_THRESHOLDS) - 1:
            best_idx = i

    best_threshold = DIFF_THRESHOLDS[best_idx]
    best_prec = precisions[best_idx]
    best_recall = recalls[best_idx]
    best_f1 = f1s[best_idx]
    best_removed = excluded_counts[best_idx]

    print(f"{malware}: Recall 최고점 하락 직전 Threshold = {best_threshold} | "
          f"P={best_prec:.4f}, R={best_recall:.4f}, F1={best_f1:.4f}, Removed={best_removed}")

    # --- 그래프 생성 --- 
    fig, ax1 = plt.subplots(figsize=(8, 5))

    # Precision / Recall / F1
    ax1.plot(DIFF_THRESHOLDS, precisions, label="Precision", linestyle='-')
    ax1.plot(DIFF_THRESHOLDS, recalls, label="Recall", linestyle='--')
    ax1.plot(DIFF_THRESHOLDS, f1s, label="F1-score", linestyle=':')
    ax1.set_xlabel("Diff Threshold (0~200)")
    ax1.set_ylabel("Score (0~1)")
    ax1.grid(True)
    ax1.legend(loc="upper left")

    # 오른쪽 y축: 제거된 함수 수
    ax2 = ax1.twinx()
    ax2.plot(DIFF_THRESHOLDS, excluded_counts, color="gray", alpha=0.5, linewidth=2.5, label="Removed Funcs")
    ax2.set_ylabel("Removed Functions")
    ax2.legend(loc="upper right")

    # 🔴 베스트 threshold 표시 (Diff, Recall, 값 텍스트 + RemovedCnt)
    ax1.scatter(
        best_threshold, best_recall,
        color="red", s=120, marker="o", edgecolors="black", linewidths=1.2, zorder=999
    )

    ax1.text(
        best_threshold + 3, best_recall + 0.02,
        f"Diff={best_threshold}\nP={best_prec:.3f}, R={best_recall:.3f}, F1={best_f1:.3f}\nRemoved={best_removed}",
        color="red", fontsize=9, fontweight="bold",
        bbox=dict(facecolor='white', edgecolor='red', boxstyle='round,pad=0.3', alpha=0.7)
    )

    plt.title(f"{malware}: Precision / Recall / F1 vs Removed Functions")
    plt.tight_layout()
    plt.savefig(OUT_DIR / f"{malware}_curve_removed.png", dpi=300)
    plt.close()

    print(f"[✓] {malware} 그래프 저장 완료 → {OUT_DIR / f'{malware}_curve_removed.png'}")

print("\n✅ 모든 악성코드 결과 저장 완료! (그래프 + metrics 텍스트)")
