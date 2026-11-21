
#coding:utf-8

import idc
import imp
import ida_auto
import ida_nalt
import ida_bytes
import idautils 
import ida_search
import idaapi
import ida_pro
import util 
imp.reload(util)
from util import *
from collections import defaultdict

import importlib
import config
importlib.reload(config)
from config import *

suspects_callsites = [] 


# def init_assert_function_list():
#     file  = ROOT_FOLDER + "assert_functions.txt"
#     with open(file,"r") as f:
#         r = f.readline().replace("\n","")
#         while r:
#             res = r.split(" ")[1]
#             assert_function_list.append(res)
#             r = f.readline().replace("\n","")


def check_redundant(block,arg1,arg2):
    global call_time
    global check_flag
    current_block = block
    
    if get_block_pred_count(current_block) == 0:
        check_flag = 0
        return 
    if block.id in checked_block_id:
        return
    start_ea = block.start_ea
    end_ea = block.end_ea
    current_ea = ida_bytes.prev_head(end_ea,start_ea)
    while  current_ea >= start_ea and current_ea != error_address:
        if idc.print_insn_mnem(current_ea) == "mov":
            if {idc.print_operand(current_ea,0),idc.print_operand(current_ea,1)} =={arg1,arg2}:
                call_time = call_time + 1
                if call_time >= 2:
                    return
        if idc.print_operand(current_ea,0) == arg1 or idc.print_operand(current_ea,0) == arg2 or idc.print_operand(current_ea,1) == arg2 or idc.print_operand(current_ea,1) == arg1:
            if idc.print_insn_mnem(current_ea) not in ["cmp","test","nop","mov"]:
                check_flag = 0
                return
        current_ea = ida_bytes.prev_head(current_ea,start_ea)
    checked_block_id.append(block.id)
    for pred_block in block.preds():
        check_redundant(pred_block,arg1,arg2)


checked_block_id = []
check_flag = 1
call_time = 0

def check_assert_condition(block):
    global checked_block_id
    global check_flag
    global call_time
    if "call" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)):
        addr = ida_bytes.prev_head(block.end_ea,block.start_ea)
        return (addr,idc.print_operand(ida_bytes.prev_head(block.end_ea,block.start_ea),0))
    if "nop" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)) and "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)):
        addr = ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)
        return (addr,idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0))
    if "jmp" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)) and "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)):
        addr = ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)
        return (addr,idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0))
    if "jmp" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)) and "mov" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)) and "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),block.start_ea)):
        arg1 = idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0)
        arg2 = idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),1)
        checked_block_id = []
        addr = ida_bytes.prev_head(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),block.start_ea)
        check_flag = 1
        call_time = 0
        check_redundant(block,arg1,arg2)
        if check_flag == 1:
            return (addr,idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),block.start_ea),0))
    if "add" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)) and \
       "rsp" == idc.print_operand(ida_bytes.prev_head(block.end_ea,block.start_ea),0) and \
       "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)):
        
        addr = ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)
        return (addr,idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0))
    if "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)) and "mov" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)):
        arg1 = idc.print_operand(ida_bytes.prev_head(block.end_ea,block.start_ea),0)
        arg2 = idc.print_operand(ida_bytes.prev_head(block.end_ea,block.start_ea),1)
        addr = ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)
        checked_block_id = []
        check_flag = 1
        call_time = 0
        check_redundant(block,arg1,arg2)
        if check_flag == 1:
            return (addr,idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0))
    return (None,None)

def get_suspect_function_callsites():
    global suspects_callsites
    done = []
    for func in idautils.Functions():
        f = idaapi.FlowChart(idaapi.get_func(func), flags=idaapi.FC_PREDS)


        meeting_list = []
        checking_dict = []

        for block in f:
            pred_id_list = [pred_block.id for pred_block in block.preds()]
            checking_dict.append(pred_id_list)
            if len(pred_id_list) > 1:
                meeting_list.append(block.id)

        for meeting_point in meeting_list:
            for pre_block_id in checking_dict[meeting_point]:
                for block in f:
                    if block.id == pre_block_id:
                        (call_ea,result) = check_assert_condition(block)
                        if call_ea:
                            callee_name = idc.print_operand(call_ea, 0)
                            caller_name = idc.get_func_name(func)
                            caller_addr = func

                            entry = {
                                "callee_name": callee_name,
                                "callsite_ea": hex(call_ea),
                                "caller_name": caller_name,
                                "caller_addr": hex(caller_addr),
                            }
                            if not any(e["callsite_ea"] == entry["callsite_ea"] for e in suspects_callsites):
                                suspects_callsites.append(entry)
    return suspects_callsites



filtered_callsites = []

def second_time_filter(suspects_callsites):

    global filtered_callsites
    callee_set = set(entry["callee_name"] for entry in suspects_callsites)

    func_stats = {}
    for entry in suspects_callsites:
        callee = entry["callee_name"]
        caller = entry["caller_name"]
        func_stats.setdefault(callee, {"call_time": 0, "caller_set": set()})
        func_stats[callee]["call_time"] += 1
        func_stats[callee]["caller_set"].add(caller)
    for entry in suspects_callsites:
        callee = entry["callee_name"]
        callsite_ea = int(entry["callsite_ea"], 16)
        caller_name = entry["caller_name"]
        stats = func_stats.get(callee, {})
        call_time = stats.get("call_time", 0)
        caller_func_num = len(stats.get("caller_set", []))
        if idaapi.get_func(callsite_ea) is None:
            continue
        f = idaapi.FlowChart(idaapi.get_func(callsite_ea), flags=idaapi.FC_PREDS)
        for block in f:
            if block.start_ea <= callsite_ea < block.end_ea:
                (addr,result) = check_assert_condition(block)

                if result and callee in idc.print_operand(addr, 0):
                    block_inst_num = get_block_inst_num(block, 4)
                    if block_inst_num <= 40:
                        filtered_callsites.append(entry)
                break
    return filtered_callsites



def save_conflict_result(filtered_callsites):
    output_dir = os.path.join(ROOT_FOLDER, "analysis_result")
    os.makedirs(output_dir, exist_ok=True)

    tmp_path = os.path.join(output_dir, "tmp_conflict_function.txt")
    total_path = os.path.join(output_dir, "total_conflict_function.txt")

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(filtered_callsites, f, indent=4, ensure_ascii=False)

    with open(total_path, "a+", encoding="utf-8") as f:
        f.write(f"{ida_nalt.get_root_filename()}\n")
        for entry in filtered_callsites:
            f.write(
                f"    callee: {entry['callee_name']}, "
                f"caller: {entry['caller_name']}, "
                f"callsite_ea: {entry['callsite_ea']}, "
                f"caller_addr: {entry['caller_addr']}\n"
            )
        f.write("\n")




def test():

    init_assert_function_list()

    get_suspect_function_callsites()
    # print("get_conflict_function")
    second_time_filter(suspects_callsites)
    save_conflict_result(filtered_callsites)

    

ida_auto.auto_wait()
test()
ida_pro.qexit(0)