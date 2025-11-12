#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, shlex, struct, subprocess, shutil
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
import pefile
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Tuple

# ===== 환경 경로만 맞춰주세요 =====
GHIDRA_HEADLESS   = "/data_add/swoo/bin_tlsh/ghidra_11.1.2_PUBLIC/ghidra_11.1.2_PUBLIC/support/analyzeHeadless"
SCRIPT_DIR        = Path(__file__).parent                 # extract_integrated_nodotenv.py 위치
BENIGN_DIR        = "/data_add/swoo/c_tlsh/dike"  # 재귀 대상 루트
OUT_DIR           = "/data_add/swoo/c_tlsh/dike_decompile_txt"  # txt 출력 루트
GHIDRA_PROJ_ROOT  = "/data_add/swoo/c_tlsh/temp"

BINARY_EXTS = {".exe", ".dll", ".bin", ".so", ".elf", ".sys"}
TIMEOUT_SEC = 0  # 0=무제한

# ===== 사전 점검(치명 실수 즉시 검출) =====
assert Path(GHIDRA_HEADLESS).exists(), f"analyzeHeadless not found: {GHIDRA_HEADLESS}"
assert os.access(GHIDRA_HEADLESS, os.X_OK), f"analyzeHeadless not executable: {GHIDRA_HEADLESS}"
assert (Path(SCRIPT_DIR) / "extract_integrated_nodotenv.py").exists(), \
       "postScript not found in -scriptPath: extract_integrated_nodotenv.py"
Path(OUT_DIR).mkdir(parents=True, exist_ok=True)
# 쓰기 가능 확인
_tmp = Path(OUT_DIR) / ".wtest"
with open(_tmp, "wb") as _f: _f.write(b"ok")
_tmp.unlink(missing_ok=True)

def is_binary_file(p: Path) -> bool:
    return p.is_file() and p.suffix.lower() in BINARY_EXTS

def iter_binaries(root: Path):
    # ★ 불필요한 파일까지 모두 탐색하던 'or True' 제거 (바이너리만 대상으로)
    for p in root.rglob("*"):
        if is_binary_file(p):
            yield p

# 어셈블리 러너의 휴리스틱과 동일한 취지
def has_real_code(pe: pefile.PE) -> bool:
    try:
        if getattr(pe.OPTIONAL_HEADER, "SizeOfCode", 0) == 0:
            return False
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore").lower()
            if name in (".text", "text") and s.SizeOfRawData > 0:
                return True
    except Exception:
        pass
    return False

def is_all_forwarders(pe: pefile.PE) -> bool:
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return False
        entries = pe.DIRECTORY_ENTRY_EXPORT.symbols
        if not entries:
            return False
        return all(getattr(e, "forwarder", None) for e in entries)
    except Exception:
        return False

def should_skip_stub(path: Path) -> bool:
    # 기존 인터페이스 보존 (다른 코드가 참조할 수 있으므로)
    skip, _reason = should_skip_stub_with_reason(path)
    return skip

def should_skip_stub_with_reason(path: Path):
    n = path.name.lower()

    # 0) 파일 매직으로 포맷 판별
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except Exception as e:
        return True, f"파일 읽기 실패: {type(e).__name__}"

    is_pe  = False
    is_elf = False
    if head[:2] == b"MZ":
        # 더 확실히: e_lfanew로 가서 'PE\0\0' 확인
        try:
            with open(path, "rb") as f:
                f.seek(0x3C)
                off = struct.unpack("<I", f.read(4))[0]
                if 0 < off <= 10_000_000:
                    f.seek(off)
                    if f.read(4) == b"PE\x00\x00":
                        is_pe = True
        except Exception:
            # MZ지만 제대로 못 읽어도, 일단 PE 휴리스틱은 생략하고 시도하도록 둠
            is_pe = False
    elif head == b"\x7fELF":
        is_elf = True

    # ---- 비-PE(ELF 포함)는 스킵하지 않고 그대로 진행 ----
    if not is_pe:
        # ELF거나 기타 포맷이면 스킵 없이 시도
        return False, ""

    # ---- 여기부터는 'PE 전용' 휴리스틱 ----
    # 1) resources 범주
    if n.endswith(".resources.dll") or "resources" in str(path.parent).lower():
        return True, "resources DLL로 판단(PE)"
    # 2) API-Set DLL
    if n.startswith("api-ms-win-") or n.startswith("ext-ms-"):
        return True, "API-Set(Forwarder) DLL 가능성 높음(PE)"
    # 3) 위성 리소스 폴더 휴리스틱
    parts = {p.lower() for p in path.parts}
    if any(len(p) == 5 and "-" in p for p in parts):
        if n.endswith(".dll") and ".resources" in n:
            return True, "위성 리소스 DLL로 판단(PE)"

    # 4) PE 구조 기반 판정 (여기서만 pefile 사용)
    try:
        pe = pefile.PE(str(path), fast_load=True)
        if not has_real_code(pe):
            return True, "실제 code 섹션(SizeOfCode=0 또는 .text 없음)(PE)"
        if is_all_forwarders(pe):
            return True, "Export 전부 forwarder (실제 코드 없음)(PE)"
        return False, ""
    except Exception as e:
        # 예전에는 여기서 스킵이었지만, PE로 보이는데 파싱만 실패한 케이스는 '시도'하게 둡니다.
        return False, f"경고: PE 파싱 실패({type(e).__name__})이지만 분석 시도"


def run_headless(ghidra_headless: str, proj_dir: Path, proj_name: str,
                 binary_path: Path, script_dir: Path,
                 out_dir_for_bin: Path, out_name: str,
                 timeout: int = 0) -> Tuple[int, Path]:
    proj_dir   = Path(proj_dir).resolve()
    binary_path= Path(binary_path).resolve()
    script_dir = Path(script_dir).resolve()
    out_dir_for_bin = Path(out_dir_for_bin).resolve()

    cmdline = (
        f'"{ghidra_headless}" '
        f'"{proj_dir}" "{proj_name}" '
        f'-import "{binary_path}" '
        f'-scriptPath "{script_dir}" '
        f'-postScript extract_integrated_nodotenv.py "{out_dir_for_bin}" "{out_name}" '
        f'-max-cpu 6 '
    )

    env = os.environ.copy()
    env.setdefault("MSYS2_ARG_CONV_EXCL", "*")
    env.setdefault("MAXMEM", "8G")
    env.pop("DISPLAY", None)
    env["JAVA_TOOL_OPTIONS"] = "-Djava.awt.headless=true"
    env["GHIDRA_FORCE_HEADLESS"] = "1"

    # 👇 여기서 출력 완전히 버림
    with open(os.devnull, "wb") as devnull:
        proc = subprocess.Popen(
            cmdline,
            shell=True,
            stdout=devnull,
            stderr=devnull,
            env=env
        )
        try:
            proc.wait(timeout=None if timeout == 0 else timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            return -9, None

    return proc.returncode, None


def cleanup_project(proj_dir: Path, proj_name: str, stop_at: Path):
    proj_dir = Path(proj_dir)
    stop_at = Path(stop_at).resolve()
    candidates = [
        proj_dir / f"{proj_name}.gpr",
        proj_dir / f"{proj_name}.rep",
        proj_dir / f"{proj_name}.crt",
        proj_dir / f"{proj_name}.lock",
    ]
    for p in candidates:
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                p.unlink(missing_ok=True)
        except Exception:
            pass

    cur = proj_dir
    try:
        while True:
            if not cur.exists():
                break
            if cur.resolve() == stop_at:
                break
            if not any(cur.iterdir()):
                cur.rmdir()
                cur = cur.parent
            else:
                break
    except Exception:
        pass

def _parallel_worker(bin_path_str: str) -> tuple:
    bin_path = Path(bin_path_str)
    try:
        rel = bin_path.relative_to(Path(BENIGN_DIR))
        out_dir_for_bin = Path(OUT_DIR) / rel.parent
        out_name = f"{rel.stem}.txt"
        out_txt = out_dir_for_bin / out_name

        # 이미 결과가 있으면 스킵
        if out_txt.exists() and out_txt.stat().st_size > 0:
            return ("skip", bin_path_str, "이미 디컴파일 결과 존재")

        # PE 매직
        # if not is_pe_magic(bin_path):
        #     return ("skip", bin_path_str, "PE 시그니처(MZ/PE) 아님")

        # 스텁/포워더/리소스 등 스킵 판정
        skip, reason = should_skip_stub_with_reason(bin_path)
        if skip:
            return ("skip", bin_path_str, reason)

        out_dir_for_bin.mkdir(parents=True, exist_ok=True)

        proj_dir = Path(GHIDRA_PROJ_ROOT) / rel.parent
        proj_dir.mkdir(parents=True, exist_ok=True)
        proj_name = rel.stem

        rc, log_path = run_headless(
            ghidra_headless=GHIDRA_HEADLESS,
            proj_dir=proj_dir,
            proj_name=proj_name,
            binary_path=bin_path,
            script_dir=SCRIPT_DIR,
            out_dir_for_bin=out_dir_for_bin,
            out_name=out_name,
            timeout=TIMEOUT_SEC
        )

        ok = (rc == 0 and out_txt.exists() and out_txt.stat().st_size > 0)
        if ok:
            return ("ok", bin_path_str)
        else:
            # 결과 파일이 비었거나 rc != 0 인 경우, 로그 경로 포함
            reason = f"Ghidra 실패(code={rc}) 또는 결과 비어있음, 로그: {log_path}"
            return ("fail", bin_path_str, reason)

    except Exception as e:
        return ("fail", bin_path_str, f"예외 발생: {type(e).__name__}: {e}")

    finally:
        try:
            rel = bin_path.relative_to(Path(BENIGN_DIR))
            proj_dir = Path(GHIDRA_PROJ_ROOT) / rel.parent
            cleanup_project(proj_dir=proj_dir, proj_name=rel.stem, stop_at=Path(GHIDRA_PROJ_ROOT))
        except Exception:
            pass

def main():
    targets = list(iter_binaries(Path(BENIGN_DIR)))
    if not targets:
        print("[!] 처리할 바이너리가 없습니다."); sys.exit(0)

    print(f"[i] 총 대상 파일: {len(targets)}개")

    USE_PARALLEL = True
    ok = 0
    skipped = 0
    failed = 0

    try:
        if not USE_PARALLEL:
            for bin_path in tqdm(targets, desc="Processing binaries", unit="file"):
                rel = bin_path.relative_to(Path(BENIGN_DIR))
                out_dir_for_bin = Path(OUT_DIR) / rel.parent
                out_name = f"{rel.stem}.txt"
                out_txt = out_dir_for_bin / out_name

                if out_txt.exists() and out_txt.stat().st_size > 0:
                    skipped += 1
                    proj_dir = Path(GHIDRA_PROJ_ROOT) / rel.parent
                    cleanup_project(proj_dir=proj_dir, proj_name=rel.stem, stop_at=Path(GHIDRA_PROJ_ROOT))
                    print(f"[-] SKIP {bin_path} | 이유: 이미 디컴파일 결과 존재")
                    continue

                # if not is_pe_magic(bin_path):
                #     skipped += 1
                #     print(f"[-] SKIP {bin_path} | 이유: PE 시그니처(MZ/PE) 아님")
                #     continue

                s, r = should_skip_stub_with_reason(bin_path)
                if s:
                    skipped += 1
                    print(f"[-] SKIP {bin_path} | 이유: {r}")
                    continue

                out_dir_for_bin.mkdir(parents=True, exist_ok=True)
                proj_dir = Path(GHIDRA_PROJ_ROOT) / rel.parent
                proj_dir.mkdir(parents=True, exist_ok=True)
                proj_name = rel.stem

                rc, log_path = run_headless(
                    ghidra_headless=str(GHIDRA_HEADLESS),
                    proj_dir=proj_dir,
                    proj_name=proj_name,
                    binary_path=bin_path,
                    script_dir=SCRIPT_DIR,
                    out_dir_for_bin=out_dir_for_bin,
                    out_name=out_name,
                    timeout=TIMEOUT_SEC
                )

                if rc == 0 and out_txt.exists() and out_txt.stat().st_size > 0:
                    ok += 1
                else:
                    failed += 1
                    print(f"[!] FAIL {bin_path} | code={rc} | 로그: {log_path}")

                cleanup_project(proj_dir=proj_dir, proj_name=proj_name, stop_at=Path(GHIDRA_PROJ_ROOT))

        else:
            PROCS = 4  # 서버 사양에 맞게 조정
            with ProcessPoolExecutor(max_workers=PROCS) as ex:
                futs = [ex.submit(_parallel_worker, str(p)) for p in targets]
                for fut in tqdm(as_completed(futs), total=len(futs), desc="Parallel Ghidra", unit="file"):
                    res = fut.result()
                    tag = res[0]
                    if tag == "skip":
                        skipped += 1
                        _, path_str, reason = res
                        print(f"[-] SKIP {path_str} | 이유: {reason}")
                    elif tag == "ok":
                        ok += 1
                    else:
                        failed += 1
                        _, path_str, reason = res
                        print(f"[!] FAIL {path_str} | {reason}")

        print(f"\n=== 완료 ===\n성공(비어있지 않은 결과): {ok}/{len(targets)}  |  스킵: {skipped}  |  실패: {failed}\n출력 루트: {OUT_DIR}\n프로젝트 루트(잔여 유지): {GHIDRA_PROJ_ROOT}")

    except KeyboardInterrupt:
        print(f"\n[!] 사용자 중단(Ctrl+C)\n지금까지 성공: {ok}/{len(targets)}  |  스킵: {skipped}  |  실패: {failed}")

if __name__ == "__main__":
    main()
