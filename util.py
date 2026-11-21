import idc
import imp
import idautils 
import idaapi
import copy
from collections import OrderedDict
import ida_funcs
import random
import json
import ida_bytes
import re
import ida_name

import importlib
import config
importlib.reload(config)
from config import *

def normalize_callee(name: str) -> str:
    return (
        name.split("@")[0]
            .replace("_", "")
            .replace("?", "")
            .replace("::", "-")
            .replace("anonymousnamespace", "")
    )

def check_condition_assert(function_addr, assert_function_list):
    f = idaapi.FlowChart(idaapi.get_func(function_addr),flags=idaapi.FC_PREDS)
    block_chains = get_must_pass_block_chains(function_addr)
    if block_chains:
        must_pass = set(b.id for b in block_chains[0])
    else:
        return 0
    for chain in block_chains[1:]:
        must_pass &= set(b.id for b in chain)
    for block in f:
        check_block = 0
        for head in idautils.Heads(block.start_ea, block.end_ea):
            if "int" in idc.print_insn_mnem(head):
                check_block = 1
            if "call" in idc.print_insn_mnem(head):
                call_function = idc.print_operand(head,0)
                if "cs:off_" in call_function:
                    static_call_fun_addr = call_function.split("cs:off_")[1]
                    call_function = idc.GetDisasm(int("0x"+static_call_fun_addr,16))
                if relative(call_function,assert_function_list):
                    check_block = 1
        if check_block == 1:
            for pred_block in block.preds():
                if pred_block.id in must_pass and cmp_constant(pred_block):
                    print(must_pass)
                    return 1
    return 0


def check_input_assert(function_addr, assert_function_list):
    f = idaapi.FlowChart(idaapi.get_func(function_addr),flags=idaapi.FC_PREDS)
    for block in f:
        check_block = 0
        for head in idautils.Heads(block.start_ea, block.end_ea):
            if "int" in idc.print_insn_mnem(head):
                check_block = 1
            if "call" in idc.print_insn_mnem(head):
                call_function = idc.print_operand(head,0)
                if "cs:off_" in call_function:
                    static_call_fun_addr = call_function.split("cs:off_")[1]
                    call_function = idc.GetDisasm(int("0x"+static_call_fun_addr,16))
                if relative(call_function,assert_function_list):
                    check_block = 1
        if check_block == 1:
            if not check_succ_block_assert(block):
                continue
            if not check_condition_input_related(block):
                continue
            return 1
    return 0


def check_succ_block_assert(block):
    if get_block_succ_count(block) ==0:
        return 1
    if get_block_succ_count(block) ==1:
        for succ_block in block.succs():
            for head in idautils.Heads(succ_block.start_ea, succ_block.end_ea):
                if "ret" in idc.print_insn_mnem(head): 
                    return 1
    return 0


def check_condition_input_related(block):
    preds = list(block.preds())
    for pred in preds:
        last_head = idc.prev_head(pred.end_ea)
        mnem_last = idc.print_insn_mnem(last_head).lower()
        if mnem_last not in ("jz", "jnz"):
            continue

        for head in idautils.Heads(pred.start_ea, pred.end_ea):
            if not idaapi.is_code(idaapi.get_full_flags(head)):
                continue

            mnem = idc.print_insn_mnem(head).lower()
            if mnem not in ("cmp", "test"):
                continue

            op1_type = idc.get_operand_type(head, 0)
            op2_type = idc.get_operand_type(head, 1)

            if op1_type != idaapi.o_reg or op2_type != idaapi.o_imm:
                continue

            reg_name = idc.print_operand(head, 0)
            func = idaapi.get_func(pred.start_ea)
            if not func:
                continue

            ok = True
            for ea in idautils.FuncItems(func.start_ea):
                if ea >= head:
                    break
                if not idaapi.is_code(idaapi.get_full_flags(ea)):
                    continue

                mnem2 = idc.print_insn_mnem(ea).lower()

                if mnem2 == "mov":
                    op1 = idc.print_operand(ea, 0)
                    op2_type = idc.get_operand_type(ea, 1)
                    if normalize_reg(op1) == normalize_reg(reg_name) and op2_type != idaapi.o_reg:            
                        ok = False
                        break
                    print(idc.GetDisasm(ea), "[" in idc.GetDisasm(ea),op1 == reg_name, normalize_reg(op1),normalize_reg(reg_name))
                    if "[" in idc.GetDisasm(ea) and normalize_reg(op1) == normalize_reg(reg_name):

                        ok = False
                        break

                if mnem2 not in ("mov", "cmp", "test"):
                    if reg_name in idc.GetDisasm(ea) or normalize_reg(reg_name) in idc.GetDisasm(ea):
                        ok = False
                        break

            if ok:
                print(idc.GetDisasm(head))
                return 1

    return 0

def normalize_reg(reg_name: str) -> str:
    reg_name = reg_name.lower().strip()
    
    if reg_name.startswith("r") and len(reg_name) >= 2 and reg_name[1].isdigit():

        base = reg_name.rstrip("dwb")
        return base

    mapping = {
        "al": "rax", "ah": "rax", "ax": "rax", "eax": "rax", "rax": "rax",
        "bl": "rbx", "bh": "rbx", "bx": "rbx", "ebx": "rbx", "rbx": "rbx",
        "cl": "rcx", "ch": "rcx", "cx": "rcx", "ecx": "rcx", "rcx": "rcx",
        "dl": "rdx", "dh": "rdx", "dx": "rdx", "edx": "rdx", "rdx": "rdx",

        "sil": "rsi", "si": "rsi", "esi": "rsi", "rsi": "rsi",
        "dil": "rdi", "di": "rdi", "edi": "rdi", "rdi": "rdi",
        "bpl": "rbp", "bp": "rbp", "ebp": "rbp", "rbp": "rbp",
        "spl": "rsp", "sp": "rsp", "esp": "rsp", "rsp": "rsp",
    }
    return mapping.get(reg_name, reg_name)

def check_assert(function_addr, assert_function_list):

    block_chains = get_must_pass_block_chains(function_addr)
    # print(block_chains)
    all_must_assert = True
    for block_chain in block_chains:
        must_walkthrough_block = block_chain
        must_assert = False
        if len(must_walkthrough_block) is not 0:
            must_assert = True
        for block in must_walkthrough_block:
            in_assert = False
            for head in idautils.Heads(block.start_ea, block.end_ea):
                if "int" in idc.print_insn_mnem(head):
                    in_assert =True
                    break
                if "call" in idc.print_insn_mnem(head):
                    call_function = idc.print_operand(head,0)
                    if "cs:off_" in call_function:
                        static_call_fun_addr = call_function.split("cs:off_")[1]
                        call_function = idc.GetDisasm(int("0x"+static_call_fun_addr,16))
                    if relative(call_function,assert_function_list):
                        in_assert = True
                        break

            must_assert = must_assert & in_assert
        all_must_assert =all_must_assert & must_assert

        return all_must_assert

def init_assert_function_list():
    file  = ROOT_FOLDER + "assert_functions.txt"
    with open(file,"r") as f:
        r = f.readline().replace("\n","")
        while r:
            res = r.split(" ")[1]
            Init_Assert_Function.append(res)
            r = f.readline().replace("\n","")

def init_part_assertion_function(input_file):
    file_assert_function = []
    for i in Init_Assert_Function:
        file_assert_function.append(i)
    file  = ROOT_FOLDER + "assert_functions.txt"
    with open(file,"r") as f:
        r = f.readline().replace("\n","")
        while r:
            if input_file == r.split(" ")[0]:
                res = r.split(" ")[1]
                file_assert_function.append(res)
            r = f.readline().replace("\n","")
    return file_assert_function

def tidy_arg(arg):
    if arg == "ax":
        return "eax"
    if arg == "bx":
        return "ebx"
    if arg == "cx":
        return "ecx"
    if arg == "dx":
        return "edx"
    arg = re.sub(r'r([89]|1[0-5])([dw]?b?)', r'r\1', arg)

    return arg.replace("dword ptr ","").replace("byte ptr ","").replace("ah","eax").replace("al","eax").replace("bh","ebx").replace("bl","ebx").replace("ch","ecx").replace("cl","ecx").replace("dh","edx").replace("dl","edx").replace("rax","eax").replace("rbx","ebx").replace("rcx","ecx").replace("rdx","edx")

def relative(func_name,func_list):
    for i in func_list:
        if i.lower() in func_name.lower():
            return True
    return False

def get_block_pred_count(block):
    count = 0
    for pred_block in  block.preds():
        count  = count + 1
    return count

def get_block_succ_count(block):
    count = 0
    for succ_block in  block.succs():
        count  = count + 1
    return count

def get_function_block_num(f):
	num = 0
	for block in f:
		num = num + 1 
	return num


def get_block_asm_and_ea(block,reverse):
    asm = []
    for head in idautils.Heads(block.start_ea, block.end_ea):
        asm.append([idc.GetDisasm(head),hex(head)])
    if reverse == True:
        asm = asm[::-1]
    return asm

def find_mandatory_blocks(target_block):
    dominate_block = []
    current_block = target_block
    max_step = 1000
    step = 0
    def check_same_id(pre_list):
        pre_list_start_ea = []
        for i in pre_list:
            pre_list_start_ea.append(i.start_ea)
        if len(set(pre_list_start_ea)) == 1:
            return True
        return False

    dominate_block.append(current_block)
    while current_block.id != 0 and get_block_pred_count(current_block) != 0:
        pre_block_list = []
        min_id = 10000
        done_block = []
        pre_block_id_list = []
        
        while not check_same_id(pre_block_list) and min_id != 0:
            if pre_block_list == []:
                for pred_block in current_block.preds():
                    pre_block_list.append(pred_block)
                    pre_block_id_list.append(pred_block.id)
                    if pred_block.id < min_id:
                        min_id = pred_block.id
            if len(pre_block_list) >300:
                break
            for j in pre_block_list:
                if j.id != min_id:
                    for prev_pre_block in j.preds() :
                        
                        update_flag = 0
                        if prev_pre_block not in done_block :
                            if prev_pre_block.id not in pre_block_id_list:
                                update_flag =  1
                                pre_block_list.append(prev_pre_block)
                                pre_block_id_list.append(prev_pre_block.id)

                                if prev_pre_block.id< min_id:
                                    min_id = prev_pre_block.id
                        if update_flag == 0 and j in pre_block_list:
                            pre_block_list.remove(j)
                    if j in pre_block_list:
                        pre_block_list.remove(j)
                    done_block.append(j)


        if len(pre_block_list) > 1:
            if get_block_pred_count(pre_block_list[0]) == 0 and pre_block_list[0] not in dominate_block:
                dominate_block.append(pre_block_list[0])
        if len(pre_block_list) == 1:
            dominate_block.append(pre_block_list[0])
        step = step +1
        if step >max_step:
            return None

        if len(dominate_block) >50:
            return None
        current_block = pre_block_list[0]
        
    return dominate_block

def get_function_block_num_f(function):
    f = idaapi.FlowChart(idaapi.get_func(function),flags=idaapi.FC_PREDS)
    return get_function_block_num(f)

def get_must_pass_block_chains(func_addr):
    
    f = idaapi.FlowChart(idaapi.get_func(func_addr),flags=idaapi.FC_PREDS)
    end_blocks = []
    block_chains = []
    for block in f:
        if get_function_block_num(f) == 1:
            end_blocks.append(block)
        elif get_block_pred_count(block) != 0 and get_block_succ_count(block) == 0:
            end_blocks.append(block)


    for end_block in end_blocks:
        dominate_block = find_mandatory_blocks(end_block)
        if dominate_block is not None:
            block_chains.append(dominate_block)

    return block_chains

def get_function_arg_num(function_addr):
    num = 0
    try:
        cfunc = idaapi.decompile(function_addr)
    except:
        return 0
    if cfunc is None:
        return 0
    locals_vars  = cfunc.get_lvars()
    for var in locals_vars:
      if var.is_arg_var:
          num = num + 1
    return num

def get_block_inst_num(block,arg_num):
    num = 0
    total_input_arg = ["ebx","ecx","r8","r9"]
    use_arg = []
    use_arg = total_input_arg[:arg_num]

    start_ea = block.start_ea
    end_ea = block.end_ea
    current_ea = ida_bytes.prev_head(end_ea,start_ea)
    flag = 0
    while current_ea >= start_ea and current_ea != error_address:
        if "call" in idc.print_insn_mnem(current_ea):
            flag = 1 
        if flag == 1 and  ("mov" in idc.print_insn_mnem(current_ea) or "lea" in idc.print_insn_mnem(current_ea)) and tidy_arg(idc.print_operand(current_ea,0)) in use_arg:
            use_arg.remove(tidy_arg(idc.print_operand(current_ea,0)))
        elif flag == 1 and ("add" in idc.print_insn_mnem(current_ea) or "sub" in idc.print_insn_mnem(current_ea) or "inc" in idc.print_insn_mnem(current_ea) or "dec" in idc.print_insn_mnem(current_ea)) and tidy_arg(idc.print_operand(current_ea,0)) in use_arg:
            pass
        elif flag == 1 and "nop" in idc.print_insn_mnem(current_ea):
            pass
        else:
            num =  num + 1
        current_ea = ida_bytes.prev_head(current_ea,start_ea)
    return num

def get_block_at_address(func_ea, target_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        print("Function not found at address:", hex(func_ea))
        return None
    f = idaapi.FlowChart(idaapi.get_func(func_ea),flags=idaapi.FC_PREDS)
    for block in f:
        if block.start_ea <= target_ea < block.end_ea:
            return block
        
    return None

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
            if idc.print_operand(current_ea,0)==arg2 and idc.print_operand(current_ea,1) == arg1:
                return
            if idc.print_operand(current_ea,0)==arg1 and idc.print_operand(current_ea,1) == arg2:
                return
        if idc.print_operand(current_ea,0) == arg1 or idc.print_operand(current_ea,0) == arg2 or idc.print_operand(current_ea,1) == arg2 or idc.print_operand(current_ea,1) == arg1:
            if idc.print_insn_mnem(current_ea) not in ["cmp","test","nop","mov"]:
                check_flag = 0
                return
        current_ea = ida_bytes.prev_head(current_ea,start_ea)
    checked_block_id.append(block.id)
    for pred_block in block.preds():
        check_redundant(pred_block,arg1,arg2)

def check_assert_condition(block):
    global checked_block_id
    global check_flag
    global call_time
    if "call" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)):
        return (idc.print_operand(ida_bytes.prev_head(block.end_ea,block.start_ea),0))
    if "nop" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)) and "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)):
        return (idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0))
    if "jmp" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)) and "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)):
        return (idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0))
    if "jmp" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)) and "mov" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)) and "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),block.start_ea)):
        arg1 = idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0)
        arg2 = idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),1)
        checked_block_id = []
        check_flag = 1
        call_time = 0
        check_redundant(block,arg1,arg2)
        if check_flag == 1:
            return (idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),block.start_ea),0))

    if "call" == idc.print_insn_mnem(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea)) and "mov" == idc.print_insn_mnem(ida_bytes.prev_head(block.end_ea,block.start_ea)):
        arg1 = idc.print_operand(ida_bytes.prev_head(block.end_ea,block.start_ea),0)
        arg2 = idc.print_operand(ida_bytes.prev_head(block.end_ea,block.start_ea),1)
        checked_block_id = []
        check_flag = 1
        call_time = 0
        check_redundant(block,arg1,arg2)
        if check_flag == 1:
            return (idc.print_operand(ida_bytes.prev_head(ida_bytes.prev_head(block.end_ea,block.start_ea),block.start_ea),0))
    return None


def change_jmp_and_call(all_asm_with_ea,target_ea):
    call_index = 0
    for asm_with_ea in all_asm_with_ea:
        call_index = call_index + 1
        asm = asm_with_ea[0]
        if asm[0] == "j":
            jmp_ea_index = 0
            find_flag = 0
            jmp_addr = asm.split("_")[-1]
            for asm_with_ea in all_asm_with_ea:
                jmp_ea_index = jmp_ea_index + 1
                if jmp_addr.lower() in asm_with_ea[1].lower():
                    find_flag = 1
                    break
            if find_flag == 1:
                if "short" in all_asm_with_ea[call_index-1][0]:
                    all_asm_with_ea[call_index-1][0] = all_asm_with_ea[call_index-1][0].replace("loc_"+jmp_addr,"INSTR"+str(jmp_ea_index)).replace("locret_"+jmp_addr.lower(),"INSTR"+str(jmp_ea_index))
                else:
                    all_asm_with_ea[call_index-1][0] = all_asm_with_ea[call_index-1][0].replace("loc_"+jmp_addr,"short INSTR"+str(jmp_ea_index)).replace("locret_"+jmp_addr.lower(),"short INSTR"+str(jmp_ea_index))
    call_index = 0
    for asm_with_ea in all_asm_with_ea:
        call_index = call_index + 1
        asm = asm_with_ea[0]
        if asm[0] == "j" and "INSTR" not in asm:
            jmp_addr = asm.split("_")[-1]
            if "short" in all_asm_with_ea[call_index-1][0]:
                all_asm_with_ea[call_index-1][0] = all_asm_with_ea[call_index-1][0].replace("loc_"+jmp_addr,"INSTRXX").replace("locret_"+jmp_addr.lower(),"INSTRXX")
            else:
                all_asm_with_ea[call_index-1][0] = all_asm_with_ea[call_index-1][0].replace("loc_"+jmp_addr,"short INSTRXX").replace("locret_"+jmp_addr.lower(),"short INSTRXX")
    init_assert_function_list()
    call_index = 0
    for asm_with_ea in all_asm_with_ea:
        call_index = call_index + 1
        asm = asm_with_ea[0]
        if asm[0:4] == "call" and asm_with_ea[1] != hex(target_ea) and not relative(asm,Init_Assert_Function):
            call_function = " ".join(asm.split(" ")[1:])
            all_asm_with_ea[call_index-1][0] =all_asm_with_ea[call_index-1][0].replace(call_function,"   FUNCTION")


    return all_asm_with_ea

def convert_asm_list_to_json(all_asm):
    return_json = OrderedDict()
    index = 1
    for i in all_asm:
        return_json[str(index)] = i[0]
        index = index + 1
    return return_json

def validity_save_num(save_assert_function,call_ea,threshold):
    call_function = idc.print_operand(call_ea,0)
    num = 0
    for i in save_assert_function:
        if i == call_function:
            num = num + 1
    if num >= threshold:
        return False
    else:
        return True

def cmp_constant(block):
    for head in idautils.Heads(block.start_ea, block.end_ea):
        if not idaapi.is_code(idaapi.get_full_flags(head)):
                    continue
        mnem = idc.print_insn_mnem(head)
        if mnem not in ("cmp", "test"):
            continue
        op1_type = idc.get_operand_type(head, 0)
        op2_type = idc.get_operand_type(head, 1)
        constant = [idaapi.o_mem, idaapi.o_imm]
        if op1_type in constant and op2_type in constant:
            if "WPP" not in idc.GetDisasm(head):
                return 1
    return 0

def get_function_insn_num(func):
    f = idaapi.FlowChart(idaapi.get_func(func),flags=idaapi.FC_PREDS)
    count = 0
    for block in f:
        ea = block.start_ea
        while ea < block.end_ea:
            if idaapi.is_code(idaapi.get_full_flags(ea)):
                count += 1
            ea = idaapi.next_head(ea, block.end_ea)
    return count

def filter_asm(asm,target_ea):
    cmp_inst =["cmp","test"]
    filter_arg = []
    filter_list = []
    filter_flag = 1
    for i in asm:
        if filter_flag == 1:
            filter_list.append(i)
        if hex(target_ea) in i:
            filter_flag = 0
    filter_list = list(reversed(filter_list))
    for i in filter_list:
        inst = i[0]
        if "j" == inst[0] or "cmp" == inst[0:2]:
            arg1 = inst.split(",")[0].split(" ")[-1]
            arg2 = inst.split(",")[1].split(" ")[1]
            filter_arg.append(tidy_arg(arg1))
            filter_arg.append(tidy_arg(arg2))


