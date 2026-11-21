import idaapi
import idautils
import idc
import ida_hexrays
import sqlite3


import importlib
import config
importlib.reload(config)
from config import *


DB_NAME = "disassembly.db"
TABLE_NAME = "disassembly"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            ea TEXT PRIMARY KEY,
            pseudocode TEXT
        )
    """)
    conn.commit()
    conn.close()



def fetch_pseudocode_from_db(ea):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(f"SELECT pseudocode FROM {TABLE_NAME} WHERE ea=?", (hex(ea),))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def save_pseudocode_to_db(ea, pseudocode):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(f"INSERT OR REPLACE INTO {TABLE_NAME} (ea, pseudocode) VALUES (?, ?)", (hex(ea), pseudocode))
    conn.commit()
    conn.close()

def get_disasm_by_func(ea):

    func = idaapi.get_func(ea)
    if not func:
        return None

    disasm_lines = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            disasm_lines.append(f"{head:08X}: {idc.GetDisasm(head)}")
    disasm_text = "\n".join(disasm_lines)
    return disasm_text


def get_pseudocode_by_func(ea):
    init_db()
    cached_code = fetch_pseudocode_from_db(ea)
    if cached_code:
        print(f"[+] Cache hit for {hex(ea)}")
        return cached_code

    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays Decompiler is not available.")
        return None

    f = idaapi.get_func(ea)
    if not f:
        print("Invalid function address.")
        return None

    try:
        cfunc = ida_hexrays.decompile(f)
        if not cfunc:
            print("Decompilation failed.")
            return None

        pseudocode_lines = []
        sv = cfunc.get_pseudocode()
        for i, sline in enumerate(sv):
            line = idaapi.tag_remove(sline.line)
            pseudocode_lines.append(f"{i+1:04d}: {line}")

        pseudocode_text = "\n".join(pseudocode_lines)

        save_pseudocode_to_db(ea, pseudocode_text)

        return pseudocode_text

    except Exception as e:
        print(f"Decompiler exception: {e}")
        return None

def get_cmp_addr(task):
    return task['context']["cmp_addr"]

def get_sink_addr(task):
    return task['context']["sink_addr"]

def get_callsite_addr(task):
    return task['context']["callee_addr"]

def get_taint_variable(task):
    return task['context']["taint_v"]

def get_cmp(task):
    return task['context']["cmp_pscode"]

def get_cmp_loc(task):
    return task['context']["cmp_lineno"]

def get_callee_code(task):
    return task['context']["callee_pscode"]

def get_callee_code_loc(task):
    return task['context']["callee_lineno"]

def get_sink(task):
    return task['context']["sink_pscode"]

def get_sink_loc(task):
    return task['context']["sink_lineno"]

def get_driver(task):
    return task['context']["sysname"]

def locate_function_from_abbr(current_function_addr, function_name):
    func = idaapi.get_func(current_function_addr)
    if not func:
        print(f"[-] Invalid function address: {hex(current_function_addr)}")
        return None

    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.print_insn_mnem(head).lower() == "call":
            target = idc.get_operand_value(head, 0)
            if target != idc.BADADDR:
                target_name = idc.get_func_name(target)
                if target_name and function_name in target_name:
                    print(f"[+] Matched function {target_name} at {hex(target)}")
                    return target
    print(f"[-] No function matching '{function_name}' found in {hex(current_function_addr)}")
    return None


def need_func_def(task, args):
    response = ""
    for arg in args:
        fun_addr = locate_function_from_abbr(int(task['context']['caller_addr'], 16), arg)

        if fun_addr:
            pseudocode = get_pseudocode_by_func(fun_addr)
            if pseudocode:
                response += f"The definition of {arg} is as follow:\n"
                response += f"```c\n{pseudocode}\n```\n"
            else:
                response += f"No pseudocode found for {arg}\n"
        else:
            response += f"No function found for {arg}\n"
    return response.strip()


def need_caller(task, args):
    response = ""
    for arg in args:
        fun_addr = locate_function_from_abbr(int(task['context']['caller_addr'], 16), arg)
        if fun_addr:
            callers = []
            for xref in idautils.XrefsTo(fun_addr):
                caller_func = idaapi.get_func(xref.frm)
                if caller_func:
                    caller_name = idc.get_func_name(caller_func.start_ea)
                    callers.append(caller_name)
            callers = list(set(callers))
            if callers:
                response += f"The callers of {arg} are:\n"
                for caller in callers:
                    response += f"- {caller}\n"
            else:
                response += f"No callers found for {arg}\n"
        else:
            response += f"No function found for {arg}\n"
    return response.strip()

import importlib
import database
importlib.reload(database)
from database import *

outer_db = DB_NAME

def get_analysis_result(task):
    case_id = task['case_id']
    res = fetch_llm_by_id(case_id,db_name=outer_db)
    return res

def get_inference(task):
    case_id = task['case_id']
    res = fetch_inference_by_id(case_id,db_name=outer_db)
    return res

def get_callsite_context(task, before=10, after=10):
    try:
        ea = int(task['context']["callee_addr"], 16)
    except Exception as e:
        print(f"[-] Invalid callee_addr: {e}")
        return ""

    if ea == idc.BADADDR:
        print("[-] BADADDR in callee_addr")
        return ""

    context_lines = []

    tmp_ea = ea
    for _ in range(before):
        tmp_ea = idc.prev_head(tmp_ea)
        if tmp_ea == idc.BADADDR:
            break
        context_lines.insert(0, f"{tmp_ea:08X}: {idc.GetDisasm(tmp_ea)}")

    context_lines.append(f"{ea:08X}: {idc.GetDisasm(ea)}")

    tmp_ea = ea
    for _ in range(after):
        tmp_ea = idc.next_head(tmp_ea)
        if tmp_ea == idc.BADADDR:
            break
        context_lines.append(f"{tmp_ea:08X}: {idc.GetDisasm(tmp_ea)}")
    return "\n".join(context_lines)