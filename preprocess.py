#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import hashlib
import struct
import shutil
from pathlib import Path
from tqdm import tqdm
import pefile

# ───────────────────────────────────────────────
# 경로 설정 (현재 스크립트 기준)
# ───────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent  # 현재 파일 기준
SRC_DIR = BASE_DIR / "dike"                 # 원본 폴더
CLEAN_DIR = BASE_DIR / "dike_clean"         # 정제본 폴더 (자동 생성)

# ───────────────────────────────────────────────
# 선택 규칙
# ───────────────────────────────────────────────
ALLOW_SYS    = False   # 드라이버(.sys) 포함 여부
ALLOW_X64    = True    # x64 포함 여부 (PalmTree x86 권장 → False)
SKIP_RECYCLE = True    # $I*, $R* 스킵
MIN_SIZE     = 1024    # 1KB 미만 파일 스킵

IMAGE_FILE_MACHINE_I386  = 0x14c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# ───────────────────────────────────────────────
# 유틸 함수
# ───────────────────────────────────────────────
def sha256_of(p: Path) -> str:
    """파일의 SHA-256 해시 계산"""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def looks_like_recycle(name: str) -> bool:
    """휴지통 임시파일 이름 ($I~, $R~) 판단"""
    u = name.upper()
    return u.startswith("$I") or u.startswith("$R")

def quick_is_pe(path: Path) -> bool:
    """간단한 PE 시그니처 검사 (MZ / PE)"""
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            off = struct.unpack("<I", f.read(4))[0]
            if off <= 0 or off > 10_000_000:
                return False
            f.seek(off)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False

def want_this_pe(path: Path) -> bool:
    """PE 파일의 아키텍처 / 서브시스템 필터"""
    try:
        pe = pefile.PE(str(path), fast_load=True)
        machine = pe.FILE_HEADER.Machine
        # x64 필터
        if not ALLOW_X64 and machine != IMAGE_FILE_MACHINE_I386:
            return False
        # .sys 드라이버 필터
        if not ALLOW_SYS and path.suffix.lower() == ".sys":
            return False
        # Native 서브시스템 제외 (부팅/커널 등)
        if getattr(pe.OPTIONAL_HEADER, "Subsystem", 3) == 1:
            return False
        return True
    except Exception:
        return False

# ───────────────────────────────────────────────
# 메인 처리
# ───────────────────────────────────────────────
def main():
    src = SRC_DIR
    dst = CLEAN_DIR
    dst.mkdir(parents=True, exist_ok=True)

    seen = set()
    kept = skipped = 0

    cand = [p for p in src.rglob("*") if p.is_file()]
    print(f"[i] 후보 파일: {len(cand)}개")

    for p in tqdm(cand, desc="Scanning", unit="file"):
        # 빠른 필터
        if SKIP_RECYCLE and looks_like_recycle(p.name):
            skipped += 1; continue
        if p.stat().st_size < MIN_SIZE:
            skipped += 1; continue
        if p.suffix.lower() not in {".exe", ".dll", ".ocx", ".cpl", ".scr", ".sys"}:
            skipped += 1; continue
        if not quick_is_pe(p):
            skipped += 1; continue
        if not want_this_pe(p):
            skipped += 1; continue

        # 중복 제거
        h = sha256_of(p)
        if h in seen:
            skipped += 1; continue
        seen.add(h)

        # 상대 경로 보존 복사
        rel = p.relative_to(src)
        out_path = dst / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(p, out_path)
            kept += 1
        except Exception:
            skipped += 1

    # 결과 출력
    print(f"\n=== 정제 완료 ===")
    print(f"총   : {len(cand)}")
    print(f"유지 : {kept}")
    print(f"제외 : {skipped}")
    print(f"정제본 위치: {dst.resolve()}")

# ───────────────────────────────────────────────
if __name__ == "__main__":
    main()
