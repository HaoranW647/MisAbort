import os
import subprocess
import importlib
import time
from time import sleep
from datetime import datetime

import config
importlib.reload(config)
from config import * 

IDA_TIMEOUT = 1800
PROG_BAR_WIDTH = 40
LOG_RUN_PATH = os.path.join(ROOT_FOLDER, "driver_run_log.txt")

TARGET_EXTS = (".elf", ".so") 

INCLUDE_NO_EXT = True 

continue_file = "" 
continue_script = False 


def _reload_config():
    try:
        importlib.reload(config)
    except Exception:
        pass


def build_ida_command(file_path, ida_script):

    base, ext = os.path.splitext(file_path)
    candidate_sys_i64 = base + ".i64"
    candidate_i64 = None
    if os.path.isfile(candidate_sys_i64):
        candidate_i64 = candidate_sys_i64

    if candidate_i64:
        target = candidate_i64
    else:
        target = file_path

    # quote paths properly
    ida_path_q = f'"{IDA_PATH}"'
    script_path_q = f'"{os.path.join(ROOT_FOLDER, ida_script)}"'
    target_q = f'"{target}"'

    cmd = f'{ida_path_q} -A -S{script_path_q} {target_q}'
    return cmd


def print_progress(current, total, filename="", width=PROG_BAR_WIDTH):
    pct = float(current) / total if total else 1.0
    if pct > 1.0:
        pct = 1.0
    filled = int(pct * width)
    bar = "[" + "#" * filled + "-" * (width - filled) + "]"
    print(f"\r{bar} {current}/{total} ({int(pct*100):3d}%)  ongoing: {filename}", end="", flush=True)


def write_run_log(entry):
    try:
        os.makedirs(os.path.dirname(LOG_RUN_PATH), exist_ok=True)
        with open(LOG_RUN_PATH, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass


def run(file_path, ida_script):
    print(f"\n\n=> starting: {file_path}  (script: {ida_script})")
    cmd = build_ida_command(file_path, ida_script)
    print("  command:", cmd)

    start_time = datetime.utcnow()
    try:
        subprocess.run(cmd, shell=True, timeout=IDA_TIMEOUT)
        status = "done"
        success = True
        msg = "ok"
    except subprocess.TimeoutExpired:
        status = "timeout"
        success = False
        msg = f"timeout after {IDA_TIMEOUT}s"
        print(f"\n  [timeout] IDA processing of {file_path} timed out after {IDA_TIMEOUT} seconds.")
    except Exception as e:
        status = "error"
        success = False
        msg = str(e)
        print(f"\n  [error] Exception while running IDA: {e}")

    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()

    log_line = f"{datetime.utcnow().isoformat()} {os.path.basename(file_path)} {ida_script} {status} {duration}s {msg}"
    write_run_log(log_line)

    sleep(1)
    print(f"  finished: {file_path} -> {status} ({duration:.1f}s)")
    return (file_path, ida_script, success, msg)


def process_all(ida_script="Caller_Intent_Filterring.py", target_exts=TARGET_EXTS):
    _reload_config()

    try:
        files = sorted(os.listdir(Binary_Path))
    except Exception as e:
        print("Error listing Binary_Path:", e)
        return []

    samples = []
    
    for f in files:
        f_lower = f.lower()
        
        if f_lower.endswith((".i64", ".idb", ".nam", ".til", ".id0", ".id1", ".id2", ".asm")):
            continue
            
        is_target = False
        if f_lower.endswith(target_exts):
            is_target = True
        
        if not is_target and INCLUDE_NO_EXT:
            if "." not in f:
                is_target = True

        if is_target:
            samples.append(f)

    if not samples:
        print(f"No samples found in Binary_Path matching {target_exts} (NoExt={INCLUDE_NO_EXT})")
        print(f"Path searched: {Binary_Path}")
        return []

    start_index = 0
    if continue_script:
        if continue_file in samples:
            start_index = samples.index(continue_file)
    else:
        if continue_file and continue_file in samples:
            start_index = samples.index(continue_file)

    to_process = samples[start_index:]
    total = len(to_process)

    print(f"Found {total} samples. Starting from index {start_index}.")
    print(f"Target Extensions: {target_exts}, Include No-Ext: {INCLUDE_NO_EXT}")
    print(f"Using script: {ida_script}")
    
    results = []

    for idx, fname in enumerate(to_process, start=1):
        fullpath = os.path.join(Binary_Path, fname)
        print_progress(idx - 1, total, filename=fname)
        res = run(fullpath, ida_script)
        results.append(res)
        print_progress(idx, total, filename=fname)
        print("")
    print(f"\nAll done. Processed {total} files with script '{ida_script}'. Log saved to: {LOG_RUN_PATH}")
    return results


if __name__ == "__main__":
    process_all(
        ida_script="Intent_context_extraction.py", 
        target_exts=(".elf", ".so")
    )