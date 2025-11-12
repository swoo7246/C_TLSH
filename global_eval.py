#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, json
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# ===== 경로 설정 =====
FUNC_DIR = Path("functions")
GT_DIR = Path("f")
DIFF_DIR = Path("sample_diff_win_tlsh")
OUT_DIR = Path("win_c_tlsh_result")
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

DIFF_THRESHOLDS = list(range(0, 201, 1))  # 0~200

# ===== Metric 계산 함수 =====
def compute_metrics(tp, fp, fn):
    prec = tp / (tp + fp) if tp + fp > 0 else 0
    recall = tp / (tp + fn) if tp + fn > 0 else 0
    f1 = 2 * prec * recall / (prec + recall) if prec + recall > 0 else 0
    return prec, recall, f1


# ===== Global threshold별 Precision/Recall/F1 계산 =====
precisions, recalls, f1s = [], [], []
removed_counts = []  # threshold별 제거된 함수 총합 저장

for dth in DIFF_THRESHOLDS:
    tp_total = fp_total = fn_total = removed_total = 0

    for malware, sha in MALWARES.items():
        gt_path = GT_DIR / f"{malware}.json"
        diff_path = DIFF_DIR / f"{sha}.jsonl"
        func_path = FUNC_DIR / f"{sha}.filtered_funcs.json"

        if not (gt_path.exists() and diff_path.exists() and func_path.exists()):
            continue

        gt_funcs = set(json.load(open(gt_path, encoding="utf-8")).keys())

        # diff map
        diff_data = []
        with open(diff_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    diff_data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        diff_map = {d["Function Name"]: d["min_diff"] for d in diff_data}

        func_data = json.load(open(func_path, encoding="utf-8"))
        all_functions = set(func_data["functions"])

        # benign (diff < threshold) 제거
        benign_funcs = {f for f, diff in diff_map.items() if diff < dth}
        remaining_funcs = all_functions - benign_funcs

        tp = len(remaining_funcs & gt_funcs)
        fp = len(remaining_funcs - gt_funcs)
        fn = len(gt_funcs - remaining_funcs)

        tp_total += tp
        fp_total += fp
        fn_total += fn
        removed_total += len(benign_funcs)

    prec, rec, f1 = compute_metrics(tp_total, fp_total, fn_total)
    precisions.append(prec)
    recalls.append(rec)
    f1s.append(f1)
    removed_counts.append(removed_total)

# ===== recall이 떨어지지 않으면서 precision 최대인 지점 찾기 =====
best_prec, best_idx = 0, 0
max_recall_so_far = 0

for i in range(len(DIFF_THRESHOLDS)):
    # recall이 이전보다 작으면 skip
    if recalls[i] < max_recall_so_far:
        continue
    # recall 유지하면서 precision 최대화
    if precisions[i] > best_prec:
        best_prec = precisions[i]
        best_idx = i
        max_recall_so_far = recalls[i]

best_threshold = DIFF_THRESHOLDS[best_idx]
best_recall = recalls[best_idx]
best_f1 = f1s[best_idx]
best_removed = removed_counts[best_idx]

# ===== 결과 저장 =====
txt_path = OUT_DIR / "global_diff_threshold_metrics.txt"
with open(txt_path, "w", encoding="utf-8") as f:
    f.write("=== Global Evaluation (Threshold 0~200) ===\n")
    f.write(f"{'Diff':>5} | {'Precision':>9} | {'Recall':>9} | {'F1':>9} | {'Removed':>9}\n")
    f.write("-" * 55 + "\n")
    for i, dth in enumerate(DIFF_THRESHOLDS):
        f.write(f"{dth:5d} | {precisions[i]:9.5f} | {recalls[i]:9.5f} | {f1s[i]:9.5f} | {removed_counts[i]:9d}\n")
    f.write("\n[Best Point: Recall 유지하며 Precision 최대]\n")
    f.write(f"Threshold = {best_threshold}\n")
    f.write(f"Precision = {best_prec:.5f}\n")
    f.write(f"Recall = {best_recall:.5f}\n")
    f.write(f"F1 = {best_f1:.5f}\n")
    f.write(f"Removed Functions = {best_removed}\n")

print("\n그래프 및 결과 저장 완료!")
print(f"그래프: {OUT_DIR}/global_diff_threshold_curve.png")
print(f"수치 데이터: {txt_path}")
print(f"Best {best_threshold} | Precision={best_prec:.4f}, Recall={best_recall:.4f}, F1={best_f1:.4f}, Removed={best_removed}")

# ===== 그래프 그리기 =====
fig, ax1 = plt.subplots(figsize=(10, 6))

# Precision / Recall / F1
ax1.plot(DIFF_THRESHOLDS, precisions, label="Precision", color="C0", linestyle='-')
ax1.plot(DIFF_THRESHOLDS, recalls, label="Recall", color="C1", linestyle='--')
ax1.plot(DIFF_THRESHOLDS, f1s, label="F1-score", color="C2", linestyle=':')
ax1.set_xlabel("Diff Threshold (0~200)")
ax1.set_ylabel("Score (0~1)")
ax1.grid(True)
ax1.legend(loc="upper left")

# 오른쪽 y축: 제거된 함수 수
ax2 = ax1.twinx()
ax2.plot(DIFF_THRESHOLDS, removed_counts, color="gray", alpha=0.6, linewidth=2.5, label="Removed Funcs")
ax2.set_ylabel("Removed Functions")
ax2.legend(loc="upper right")

# 베스트 threshold 표시 (Diff, 성능지표, 제거된 함수 수 포함)
ax1.scatter(
    best_threshold, best_prec,
    color="red", s=120, marker="o", edgecolors="black", linewidths=1.2, zorder=999
)
ax1.text(
    best_threshold + 3, best_prec + 0.02,
    f"Diff={best_threshold}\nP={best_prec:.3f}, R={best_recall:.3f}, F1={best_f1:.3f}\nRemoved={best_removed}",
    color="red", fontsize=9, fontweight="bold",
    bbox=dict(facecolor='white', edgecolor='red', boxstyle='round,pad=0.3', alpha=0.7)
)

plt.title("Global Precision / Recall / F1 vs Diff Threshold\nwith Removed Function Count")
plt.tight_layout()
plt.savefig(OUT_DIR / "global_diff_threshold_curve.png", dpi=300)
plt.close()
