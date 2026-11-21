import idaapi
import idautils
import idc
import imp
import util
import ida_nalt
import os
import time
import json
import config
imp.reload(util)
imp.reload(config)
from util import *
from config import *




# ====== Logging function ======
def log(msg):
    log_line = f"{msg}\n"
    print(log_line, end="")
    with open(Slicing_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(log_line)


def save_positive(asm_json, save_path, input_file, call_function, current_saved_files):
    with open(f"{save_path}\\{input_file}_{call_function}_{current_saved_files}.json", "w") as f:
        json.dump(asm_json, f, indent=4)


def get_succ_sample(target_block):
    succ_story_block = []
    succ_story_block_ea = []
    used_current_block_id = []
    story_number = 1
    save_flag = 0
    current_block = target_block
    pre_current = None
    used_current_block_id.append(current_block.id)
    pre_current = current_block.id
    while get_block_succ_count(current_block) != 0 and story_number != 2:
        for succ_current_block in current_block.succs():
            pre_current = current_block.id
            if succ_current_block.start_ea not in succ_story_block_ea:
                if story_number == 2:
                    break
                if succ_current_block.id not in used_current_block_id:
                    succ_story_block.append(succ_current_block)
                    succ_story_block_ea.append(succ_current_block.start_ea)
                    story_number += 1
                    save_flag = 1
                    current_block = succ_current_block
                    used_current_block_id.append(current_block.id)
            if pre_current == current_block.id:
                return succ_story_block
        if save_flag == 0:
            min_id = 1000
            for succ_current_block in current_block.succs():
                if succ_current_block.id < min_id:
                    min_id = succ_current_block.id
                    if current_block.id not in used_current_block_id:
                        current_block = succ_current_block
                    used_current_block_id.append(current_block.id)
    return succ_story_block


def sample_prepare(func_ea, target_ea, save_path, index, function_name=None):
    target_block = get_block_at_address(func_ea, target_ea)
    pre_story_asm = []
    if target_block:
        mandatory_blocks = find_mandatory_blocks(target_block)
    if mandatory_blocks is None:
        return False
    if len(mandatory_blocks) == 1:
        return False
    for block in mandatory_blocks:
        asm = get_block_asm_and_ea(block, reverse=True)
        for instr in asm:
            pre_story_asm.append(instr)
    if len(pre_story_asm) > 100:
        pre_story_asm = pre_story_asm[0:100][::-1]
    else:
        pre_story_asm = pre_story_asm[::-1]
    succ_story_asm = []
    succ_story_block = get_succ_sample(target_block)
    for block in succ_story_block:
        asm = get_block_asm_and_ea(block, reverse=False)
        for instr in asm:
            succ_story_asm.append(instr)
    all_asm = pre_story_asm + succ_story_asm
    all_asm = change_jmp_and_call(all_asm, target_ea)
    asm_json = convert_asm_list_to_json(all_asm)
    if len(asm_json) < 6:
        return False
    input_file = os.path.basename(ida_nalt.get_input_file_path()).replace(".exe", "").replace("_", "").replace("-", "")
    save_positive(asm_json, save_path, input_file, function_name, index)
    return True


def main():
    start_time = time.time()

    index = 0
    json_file = os.path.join(ROOT_FOLDER, "analysis_result", "total_conflict_function.json")

    if not os.path.exists(json_file):
        raise FileNotFoundError(f"{json_file} does not exist")

    with open(json_file, "r", encoding="utf-8") as f:
        records = json.load(f)

    number = 0
    failed_records = []

    log("========== Batch processing started ==========")
    log("file: {}".format(ida_nalt.get_root_filename()))

    for idx, rec in enumerate(records, 1):
        success = 0
        file_name = rec.get("file")
        if not file_name:
            failed_records.append({"record": rec, "error": "Missing file name"})
            log(f"[{idx}] Missing file name, skipped")
            continue

        if file_name == ida_nalt.get_root_filename():
            number += 1
            target_file = os.path.join(ROOT_FOLDER, "kernel_drivers", file_name)
            caller_name = rec.get("caller").split("@")[0].replace("_", "").replace("?", "").replace("::", "-").replace("anonymousnamespace", "")
            callee_name = rec.get("callee").split("@")[0].replace("_", "").replace("?", "").replace("::", "-").replace("anonymousnamespace", "")
            caller_ea = rec.get("caller_addr")
            target = rec.get("callsite_ea")
            save_name = f"{caller_name}_{callee_name}_{target}"
            caller = int(caller_ea, 0) if isinstance(caller_ea, str) else int(caller_ea)
            targ = int(target, 0) if isinstance(target, str) else int(target)
            if not all([caller_name, caller_ea, target]):
                failed_records.append({"record": rec, "error": "Missing caller_name/caller_ea/target"})
                log(f"[{idx}] Missing caller_name/caller_ea/target, skipped")
                continue

            try:
                result = sample_prepare(caller, targ, save_dir, index, save_name)
            except Exception as e:
                failed_records.append({"record": rec, "error": str(e)})
                log(f"[{idx}] Error during execution: {e}")
            else:
                if result:
                    index += 1
                    success = 1
                else:
                    failed_records.append({"record": rec, "error": "no sample"})
                    log(f"[{idx}] No sample generated: {save_name}")

    end_time = time.time()
    duration = end_time - start_time
    time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

    log(f"Batch completed. Success: {number - len(failed_records)}  Failed: {len(failed_records)}")
    log(f"End time: {time_str}")
    log(f"Total duration: {duration:.2f} seconds")
    log("========== Batch processing finished ==========\n")

    if failed_records:
        fail_path = os.path.join(ROOT_FOLDER, "log", "slicing", "failed_backward_slicing.json")
        
        if os.path.exists(fail_path):
            with open(fail_path, "r", encoding="utf-8") as f:
                try:
                    existing_records = json.load(f)
                    if not isinstance(existing_records, list):
                        existing_records = []
                except json.JSONDecodeError:
                    existing_records = []
        else:
            existing_records = []

        combined_records = existing_records + failed_records

        with open(fail_path, "w", encoding="utf-8") as f:
            json.dump(combined_records, f, indent=4, ensure_ascii=False)


ida_auto.auto_wait()
main()
ida_pro.qexit(0)