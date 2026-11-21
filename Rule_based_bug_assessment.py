import angr 
import json 
import logging 
import angr 
import os 
import importlib 

import database 
importlib.reload(database) 
from database import * 

import config 
importlib.reload(config) 
from config import * 

logging.getLogger("angr").setLevel(logging.CRITICAL)
DB_NAME = "static_analysis.db" 

def load_json(file_path): 
	with open(file_path, "r", encoding="utf-8") as f: 
		return json.load(f)

def get_reg_id_by_name(proj, reg_name): 
	if not reg_name: 
		return None

	reg_name = reg_name.lower()
	md = proj.arch.capstone 

	for reg_id in range(1, 2048): 
		name = md.reg_name(reg_id) 
		if not name: 
			continue 
		if name.lower() == reg_name: 
			return reg_id 
	return None 



def debug_print_cfg_functions(cfg):
    print("\n" + "="*50)
    print(f"[*] DEBUG: Listing all {len(cfg.kb.functions)} functions in CFG KB")
    print("="*50)
    sorted_funcs = sorted(cfg.kb.functions.items(), key=lambda x: x[0])
    
    for func_addr, func_obj in sorted_funcs:
        print(f"Addr: {hex(func_addr):<18} | Name: {func_obj.name}")
    print("="*50 + "\n")

def check_block_chain_ret_with_cfg(cfg, proj, addr): 
	
	func = cfg.kb.functions.floor_func(addr) 
	if not func: 
		return 0
	current_block = None 
	for block in func.graph.nodes():
		if block.addr <= addr < block.addr + block.size: 
			current_block = block 
			break 
	if not current_block: 
		return 0

	successors = list(func.graph.successors(current_block)) 
	if len(successors) == 1: 
		succ_block = successors[0] 
		b_succ = proj.factory.block(succ_block.addr, size=succ_block.size) 
		insns_succ = b_succ.capstone.insns 

		if insns_succ and insns_succ[0].mnemonic in ("cmp", "test"): 
			for next_block in func.graph.successors(succ_block): 
				b_next = proj.factory.block(next_block.addr, size=next_block.size) 
				mnemonics = [ins.mnemonic for ins in b_next.capstone.insns] 
				if 'ret' in mnemonics or 'retn' in mnemonics:
					return 0

		if 1 <= len(insns_succ) <= 2:
			for next_block in func.graph.successors(succ_block):
				b_next = proj.factory.block(next_block.addr, size=next_block.size) 
				mnemonics = [ins.mnemonic for ins in b_next.capstone.insns] 
				if 'ret' in mnemonics or 'retn' in mnemonics:
					return 0

	while True: 
		successors = list(func.graph.successors(current_block)) 
		if len(successors) != 1: 
			return 1 

		next_block = successors[0] 
		b = proj.factory.block(next_block.addr, size=next_block.size) 
		mnemonics = [insn.mnemonic for insn in b.capstone.insns] 

		if 'ret' in mnemonics or 'retn' in mnemonics: 
			return 0 

		if len(b.capstone.insns) == 1 and mnemonics[0].startswith('j'): 
			current_block = next_block 
			continue 
		return 1 

def find_previous_cmps(proj, cfg, caller_addr, call_addr, end_addr, special_flag): 
	print("start finding compares ... ")
	cmp_register_set = set() 
	cmp_addr_set = {}
	trace_register_set = set() 
	trace_addr_set = {}

	node = cfg.get_any_node(call_addr, anyaddr=True) 

	if not node:
		log(f"[!] no {hex(call_addr)} basic block")
		return cmp_register_set, cmp_addr_set, trace_register_set, trace_addr_set 
		
	visited = set() 
	worklist = [(node, False)]

	while worklist: 
		debug = 0 
		block_node, found_cmp = worklist.pop() 
		if (block_node.addr, found_cmp) in visited: 
			continue 
		visited.add((block_node.addr, found_cmp)) 

		block = proj.factory.block(block_node.addr) 
		new_regs = set()
		if not found_cmp: 
			insns = list(block.capstone.insns) 
			for idx in range(len(insns) - 1, -1, -1):
				insn = insns[idx] 
				if insn.address >= call_addr: 
					continue
				if insn.mnemonic in ["cmp", "test", "bt"] and "rip" not in insn.op_str: 
					if idx > 0: 
						prev_insn = insns[idx - 1] 
						if "rip" in str(prev_insn): 
							found_cmp = False 
							new_regs.clear() 
							break 

					if "WPP" not in str(insn) and caller_addr < insn.address < end_addr: 
						regs_in_insn = set() 
						for op in insn.operands: 
							if hasattr(op, "mem") and hasattr(op.mem, "base") and op.mem.base != 0: 
								reg_name = proj.arch.capstone.reg_name(op.mem.base) 
								if reg_name: 
									regs_in_insn.add(op.mem.base) 
									cmp_addr_set.setdefault(op.mem.base, []).append(insn.address) 
							elif hasattr(op, "reg") and op.reg != 0: 
								reg_name = proj.arch.capstone.reg_name(op.reg) 
								if reg_name: 
									regs_in_insn.add(op.reg) 
									cmp_addr_set.setdefault(op.reg, []).append(insn.address) 
						if special_flag == 1 and regs_in_insn: 
							reg_name_map = {proj.arch.capstone.reg_name(r).lower(): r for r in regs_in_insn} 
							if "rdx" in reg_name_map: 
								rcx_reg = get_reg_id_by_name(proj, "rcx") 
								if rcx_reg: 
									regs_in_insn.add(rcx_reg) 
									cmp_addr_set.setdefault(rcx_reg, []).append(insn.address) 
							if "rcx" in reg_name_map: 
								rdx_reg = get_reg_id_by_name(proj, "rdx") 
								if rdx_reg: 
									regs_in_insn.add(rdx_reg) 
									cmp_addr_set.setdefault(rdx_reg, []).append(insn.address) 
							if "edx" in reg_name_map: 
								ecx_reg = get_reg_id_by_name(proj, "ecx") 
								if ecx_reg: 
									regs_in_insn.add(ecx_reg) 
									cmp_addr_set.setdefault(ecx_reg, []).append(insn.address) 
								ecx_reg = get_reg_id_by_name(proj, "rcx") 
								if ecx_reg: 
									regs_in_insn.add(ecx_reg) 
									cmp_addr_set.setdefault(ecx_reg, []).append(insn.address) 
							if "ecx" in reg_name_map: 
								edx_reg = get_reg_id_by_name(proj, "edx") 
								if edx_reg: 
									regs_in_insn.add(edx_reg) 
									cmp_addr_set.setdefault(edx_reg, []).append(insn.address) 
						if regs_in_insn: 
							new_regs.update(regs_in_insn) 
							found_cmp = True 
							break
		if new_regs: 
			cmp_register_set.update(new_regs) 
			for new_reg in new_regs: 
				stop = 0 
				insns = block.capstone.insns 
				insns_len = len(insns) 

				for idx in range(insns_len - 1, -1, -1): 
					if stop == 1: 
						break 
					insn = insns[idx] 

					if insn.mnemonic == "mov" and len(insn.operands) == 2 and "rip" not in insn.op_str: 
						dst, src = insn.operands 
						match_dst = (hasattr(dst, "reg") and dst.reg == new_reg) or \
									(hasattr(dst, "mem") and hasattr(dst.mem, "base") and dst.mem.base == new_reg) 
						if match_dst: 
							if hasattr(src, "reg") and src.reg != 0: 
								trace_register_set.add(src.reg) 
								trace_addr_set.setdefault(src.reg, []).append(insn.address) 
								stop = 1 
							elif hasattr(src, "mem") and hasattr(src.mem, "base") and src.mem.base != 0: 
								trace_register_set.add(src.mem.base) 
								trace_addr_set.setdefault(src.mem.base, []).append(insn.address) 
								stop = 1 

					if insn.mnemonic in ["cmp", "test", "bt"] and idx > 0: 
						prev_insn = insns[idx - 1] 
						if prev_insn.mnemonic == "mov" and len(prev_insn.operands) == 2: 
							dst, src = prev_insn.operands 
							match_src = (hasattr(src, "reg") and src.reg == new_reg) or \
										(hasattr(src, "mem") and hasattr(src.mem, "base") and src.mem.base == new_reg) 
							if match_src: 
								if hasattr(dst, "reg") and dst.reg != 0: 
									trace_register_set.add(dst.reg) 
									trace_addr_set.setdefault(dst.reg, []).append(prev_insn.address) 
								elif hasattr(dst, "mem") and hasattr(dst.mem, "base") and dst.mem.base != 0: 
									trace_register_set.add(dst.mem.base) 
									trace_addr_set.setdefault(dst.mem.base, []).append(prev_insn.address) 
		if not found_cmp: 
			for pred in block_node.predecessors: 
				worklist.append((pred, found_cmp)) 
	print("finish finding compares ... ")
	return cmp_register_set, cmp_addr_set, trace_register_set, trace_addr_set 

import sys 
import time 
from angr.errors import SimEngineError 

def step_and_skip_calls(proj, simgr): 
	new_active = [] 
	for state in simgr.active: 
		try: 
			block = proj.factory.block(state.addr, opt_level=0, backup_state=state) 
		except SimEngineError: 
			continue 

		skip = False 
		for insn in block.capstone.insns: 
			if insn.mnemonic.startswith("call"): 
				print(f"[-] Skipping call at {hex(insn.address)}") 
				state.regs.rip = insn.address + insn.size 
				skip = True 
				break 

		if skip: 
			new_active.append(state) 
		else: 
			try: 
				succ = proj.factory.successors(state) 
				new_active.extend(succ.successors) 
			except: 
				pass 

	simgr.active = new_active 
	return simgr 

def trace_register_path(proj, start_addr, cmp_register, call_addr, end_addr, max_time=120, step_interval=1): 
	state = proj.factory.blank_state(addr=call_addr) 
	state.regs.rip = call_addr 
	simgr = proj.factory.simulation_manager(state) 
	results = [] 
	visited_insns = set() 
	flag = 0 
	start_time = time.time() 
	skip_flag = 0 

	i = 0 
	while simgr.active: 
		i = i + 1 
		try: 
			active_addrs= [s.addr for s in simgr.active] 
		except: 
			return (results, 0) 
		if time.time() - start_time > max_time: 
			log(f"Warning: Maximum time limit of {max_time} seconds reached. Stopping...") 
			break 
		for s in simgr.active: 
			# print(hex(s.addr)) 
			try: 
				block = proj.factory.block(s.addr) 
			except SimEngineError as e: 
				log(f"Warning: {str(e)} at address {hex(s.addr)}. Skipping...") 
				continue 
			try: 
				insns = block.capstone.insns 
			except KeyError: 
				print(f"Skipping address {hex(s.addr)} due to capstone error") 
				continue 
			for insn in block.capstone.insns: 
				load_flag = 0 
				asm_line = f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}" 
				# print(asm_line) 
				if insn.address < start_addr: 
					continue 
				used = False 
				for op in insn.operands: 
					if hasattr(op, "reg") and op.reg == cmp_register: 
						used = True 
						break 
				if "["+insn.reg_name(cmp_register)+"]" in insn.op_str: 
					load_flag = 1 
					used = True 
				if used and insn.address not in visited_insns: 
					visited_insns.add(insn.address) 
					if insn.mnemonic == "xor" and results == [] and insn.address > call_addr and insn.address< end_addr: 
						flag = 1 
					elif insn.mnemonic == "mov" and results == [] and insn.address > call_addr and insn.address< end_addr and load_flag == 0: 
						if hasattr(insn.operands[0], "mem") and hasattr(insn.operands[0].mem, "base") and insn.operands[0].mem.base != 0: 
							if cmp_register == insn.operands[0].mem.base: 
								flag = 1 
						elif hasattr(insn.operands[0], "reg") and insn.operands[0].reg != 0: 
							if cmp_register == insn.operands[0].reg: 
								flag = 1 
					if insn.address > call_addr and "cmp" not in asm_line and "test" not in asm_line and insn.address< end_addr: 
						results.append(asm_line) 
					if insn.reg_name(cmp_register)== "ebp" or insn.reg_name(cmp_register)== "rbp": 
						skip_flag = 1 
			try: 
				step_and_skip_calls(proj,simgr) 
			except SimEngineError as e: 
				log(f"Warning: {str(e)} at address {hex(s.addr)}. Skipping...") 
				results.append("") 
				return (results, 0) 
		if len(results) % step_interval == 0: 
			sys.stdout.write(f"\rProcessed {len(results)} instructions...") 
			sys.stdout.flush() 
		log("\n") 
		if skip_flag == 1: 
			flag = 0 
	return (results, flag) 

import capstone 

def get_register_name(proj): 
	arch = proj.arch 
	for offset, name in arch.register_names.items(): 
		print(f"{offset}: {name}") 

def test_trace_register_path(proj, start_addr, cmp_register, call_addr, end_addr, max_time=120, step_interval=1): 
	print("start_addr:{}".format(hex(call_addr))) 
	state = proj.factory.blank_state(addr=call_addr) 
	state.regs.rip = call_addr 
	simgr = proj.factory.simulation_manager(state) 
	for i in range(30): 
		simgr = step_and_skip_calls(proj,simgr) 
		active_addrs= [s.addr for s in simgr.active] 
		print(f"step:{i+1},Active addresses: {hex(active_addrs[0])}") 
		for s in simgr.active: 
			block = proj.factory.block(s.addr) 
			for insn in block.capstone.insns: 
				asm_line = f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}" 
				print(asm_line) 
				input() 
	return None,0 

def log(r): 
	with open("angr_log.txt", "a+", encoding="utf-8") as output_file: 
		output_file.write(r) 
		output_file.flush() 

def get_all_functions(cfg):  
	function_list = {} 
	for func_addr, func in cfg.kb.functions.items(): 
		function_list[func.name] = f"0x{func_addr:X}".lower() 
	return function_list 

skip_call_addr = [] 

def get_special_function_addr(cfg): 
	addr_list = [] 
	special_functions = ["_security_check_cookie"] 
	function_list = get_all_functions(cfg) 
	for function in special_functions: 
		if function in function_list: 
			addr_list.append(function_list[function]) 
			return addr_list 


import angr 
import claripy 
import re 
def trace_symbolic_memory_access_addtion(proj, call_addr, capstone_reg_id, start_addr, max_steps=100, step_interval=1): 
	reg_name = proj.arch.capstone.reg_name(capstone_reg_id) 
	if reg_name not in proj.arch.registers: 
		print(f"[!] Unrecognized register: {reg_name}") 
		return [] 
	reg_offset = proj.arch.registers[reg_name][0] 
	print("\nstart_addr:{}".format(hex(start_addr))) 

	state = proj.factory.blank_state(addr=start_addr) 
	state.regs.rip = start_addr 
	sym_reg = claripy.BVS(f'sym_{reg_name}', proj.arch.bits) 
	state.registers.store(reg_offset, sym_reg) 

	accesses = [] 
	triggered = {"enabled": False} 
	step_count = {"count": 0} 
	pin_step = -1 

	# mem_read / mem_write callback 
	def mem_read_callback(state): 
		global pin_step 
		if not state.globals.get('target_path', False): 
			return 
		addr = state.inspect.mem_read_address 
		expr = addr if isinstance(addr, claripy.ast.Base) else claripy.BVV(addr, proj.arch.bits) 
		if sym_reg.variables & expr.variables: 
			insn = proj.factory.block(state.addr, num_inst=1).capstone.insns[0] 
			if "+ 0x30]" in insn.op_str or "+ 0x38]" in insn.op_str: 
				return 
			if step_count["count"] != pin_step: 
				print(step_count["count"], pin_step) 
				print(f"[!] Memory READ depends on {reg_name} at {hex(state.addr)}: {addr}") 
				accesses.append(f"READ at {hex(state.addr)}") 

	def mem_write_callback(state): 
		global pin_step 
		if not state.globals.get('target_path', False): 
			return 
		addr = state.inspect.mem_write_address 
		expr = addr if isinstance(addr, claripy.ast.Base) else claripy.BVV(addr, proj.arch.bits) 
		if sym_reg.variables & expr.variables: 
			insn = proj.factory.block(state.addr, num_inst=1).capstone.insns[0] 
			if "+ 0x30]" in insn.op_str or "+ 0x38]" in insn.op_str: 
				return 
			if step_count["count"] != pin_step: 
				print(f"[!] Memory WRITE depends on {reg_name} at {hex(state.addr)}: {addr}") 
				accesses.append(f"WRITE at {hex(state.addr)}") 

	# instruction callback 
	def insn_callback(state): 
		global pin_step 
		block = proj.factory.block(state.addr) 
		insn_addrs = [insn.address for insn in block.capstone.insns] 
		if call_addr in insn_addrs and not triggered["enabled"]: 
			print(f"\n[+] Reached call_addr {hex(call_addr)} at block {hex(state.addr)}") 
			triggered["enabled"] = True 
			state.globals['target_path'] = True 
			pin_step = step_count["count"] 
		pattern = r"\b" + re.escape(reg_name) 
		for insn in block.capstone.insns: 
			if re.search(pattern, insn.op_str.lower()): 
				print(f"[!] Memory WRITE/READ: {insn.mnemonic} {insn.op_str} {reg_name} at {hex(insn.address)}") 
				accesses.append(f"WRITE/WRITE at {hex(insn.address)}") 

		state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read_callback) 
		state.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write_callback) 

		if triggered["enabled"]: 
			for insn in block.capstone.insns: 
				if insn.mnemonic == "push": 
					operand = insn.op_str.lower() 
					try: 
						reg_expr = getattr(state.regs, operand) 
						if (sym_reg.variables & reg_expr.variables) and step_count["count"] != pin_step: 
							print(f"[0x{insn.address:x}] push {operand} ← variable") 
							accesses.append(f"PUSH at {hex(insn.address)}") 
					except AttributeError: 
						pass 

	state.inspect.b('instruction', when=angr.BP_BEFORE, action=insn_callback) 

	simgr = proj.factory.simulation_manager(state) 
	timeout = 60 
	start_time = time.time() 
	while simgr.active and step_count["count"] < max_steps and len(accesses) < 3: 
		if time.time() - start_time > timeout: 
			print(f"[!] Timeout: Exceeded {timeout} seconds.") 
			break 
		try: 
			simgr.step() 
		except: 
			print(f"[!] error") 
			break 
		for s in simgr.active[:]: 
			if not s.globals.get('target_path', False) and triggered["enabled"]: 
				simgr.active.remove(s) 
		step_count["count"] += 1 
		if step_count["count"] % step_interval == 0: 
			sys.stdout.write(f"\rProcessed {step_count['count']} instructions...") 
			sys.stdout.flush() 
	return accesses 

def trace_symbolic_memory_access(proj, call_addr, capstone_reg_id, max_steps=100,step_interval=1): 
	reg_name = proj.arch.capstone.reg_name(capstone_reg_id) 
	if reg_name not in proj.arch.registers: 
		print(f"[!] Unrecognized register: {reg_name}") 
		return [] 

	reg_offset = proj.arch.registers[reg_name][0] 
	print(" start_addr:{}".format(hex(call_addr))) 

	state = proj.factory.blank_state(addr=call_addr) 
	state.regs.rip = call_addr 
	sym_reg = claripy.BVS(f'sym_{reg_name}', proj.arch.bits) 
	state.registers.store(reg_offset, sym_reg) 

	accesses = [] 

	def mem_read_callback(state): 
		addr = state.inspect.mem_read_address 
		expr = addr if isinstance(addr, claripy.ast.Base) else claripy.BVV(addr, proj.arch.bits) 
		if sym_reg.variables & expr.variables: 
			insn = proj.factory.block(state.addr, num_inst=1).capstone.insns[0] 
			if "+ 0x30]" in insn.op_str or "+ 0x38]" in insn.op_str: 
				return 
			print(f"[!] Memory READ depends on {reg_name} at {hex(state.addr)}: {addr}") 
			accesses.append(f"READ at {hex(state.addr)}") 

	def before_insn(state): 
		ip = state.addr 
		block = proj.factory.block(ip, num_inst=1)
		insn = block.capstone.insns[0] 
		print(f"[INSN] {hex(ip)}: {insn.mnemonic} {insn.op_str}") 
		print(block.vex.pp()) 

	def mem_write_callback(state): 
		addr = state.inspect.mem_write_address 
		expr = addr if isinstance(addr, claripy.ast.Base) else claripy.BVV(addr, proj.arch.bits) 
		if sym_reg.variables & expr.variables: 
			insn = proj.factory.block(state.addr, num_inst=1).capstone.insns[0] 
			print(f"[!] Memory WRITE depends on {reg_name} at {hex(state.addr)}: {addr}") 
			accesses.append(f"WRITE at {hex(state.addr)}") 

	def insn_callback(state): 
		addr = state.addr 
		block = proj.factory.block(addr, num_inst=1) 
		insn = block.capstone.insns[0] 
		if insn.address != call_addr: 
			if insn.mnemonic == "push": 
				operand = insn.op_str.lower() 
				try: 
					reg_expr = getattr(state.regs, operand) 
					if is_symbolic(reg_expr, sym_var): 
						print(f"[0x{insn.address:x}] push {operand} ← variable") 
						accesses.append(f"PUSH at {hex(state.addr)}") 
				except AttributeError: 
					pass 


	state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_read_callback) 
	state.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_write_callback) 
	state.inspect.b('instruction', when=angr.BP_BEFORE, action=insn_callback) 

	simgr = proj.factory.simulation_manager(state) 
	step_count = 0 
	timeout = 60 
	start_time = time.time() 

	while simgr.active and step_count < max_steps and len(accesses) < 3: 
		if time.time() - start_time > timeout: 
			print(f"[!] Timeout: Exceeded {timeout} seconds.") 
			break 
		step_count += 1 
		try: 
			simgr.step() 
		except: 
			print(f"[!] error") 
			break 

		if step_count % step_interval == 0: 
			sys.stdout.write(f"\r Processed {step_count} instructions...") 
			sys.stdout.flush() 

	return accesses 


class SkipFunction(angr.SimProcedure): 
	def run(self, *args, **kwargs): 
		return 

import time 

def analyze_binary(proj, cfg, e, special_flag = 0): 
	global skip_call_addr 
	start = time.time() 
	final_cmp_addr = [] 
	final_sink_addr = [] 
	skip_call_addr = get_special_function_addr(cfg) 
	caller_addr = int(e["caller_address"], 16) 
	call_addr = int(e["call_address"], 16) 
	try: 
		func = cfg.kb.functions[caller_addr] 
	except Exception as e: 
		return 
	end_addr = func.addr + func.size 
	# find cmp & register 
	log(f"\n[*] analyzing {e['caller_function']} at {hex(call_addr)} calling {e['target_function']}\n") 

	all_accesses = [] 
	cmp_register_set, cmp_addr_set, trace_register_set, trace_addr_set = find_previous_cmps(
		proj, cfg, caller_addr, call_addr,end_addr, special_flag
	) 
	if not cmp_register_set: 
		log("[!] no cmp found\n") 
		return 

	register_addr_hex = set() 
	for i in cmp_register_set: 
		for j in cmp_addr_set[i]: 
			register_addr_hex.add(hex(j)) 
	trace_addr_hex = set() 
	for i in trace_register_set: 
		for j in trace_addr_set[i]: 
			trace_addr_hex.add(hex(j)) 

	log(f"[*] at {str(register_addr_hex)} found cmp, target: {str(cmp_register_set)}\n") 
	log(f"[*] at {str(trace_addr_hex)} found more cmp，target: {str(trace_register_set)}\n") 

	if len(trace_register_set)+ len(cmp_register_set) > 15: 
		return 

	# hook 
	for func_addr, _ in cfg.kb.functions.items(): 
		if func_addr == proj.entry: 
			continue 
		try: 
			proj.hook(func_addr, SkipFunction()) 
		except Exception as e: 
			print(f"[!] Hook failed at {hex(func_addr)}: {e}") 

	# symbolic exec 
	for cmp_register in cmp_register_set: 
		if cmp_register != 1: 
			log("searching: {} \n".format(cmp_register)) 
			new_accesses = trace_symbolic_memory_access(proj, call_addr, cmp_register) 
			all_accesses = all_accesses + new_accesses 
			log(f"[*] Found memory accesses tied to symbolic reg {cmp_register}({proj.arch.capstone.reg_name(cmp_register)}): {new_accesses}\n") 
			if len(new_accesses) != 0: 
				for c_a in cmp_addr_set[cmp_register]: 
					final_cmp_addr.append(hex(c_a)) 
				final_sink_addr = final_sink_addr + new_accesses 

	for cmp_register in trace_register_set: 
		if cmp_register != 1: 
			start_addrs = trace_addr_set[cmp_register] 
			for start_addr in start_addrs: 
				log("searching {}, address: {}\n".format(cmp_register,hex(start_addr))) 
				new_accesses = trace_symbolic_memory_access_addtion(proj, call_addr, cmp_register, start_addr) 
				all_accesses = all_accesses + new_accesses 
				log(f"[*] Found memory accesses tied to symbolic reg {cmp_register}({proj.arch.capstone.reg_name(cmp_register)}): {new_accesses}\n") 
				if len(new_accesses) != 0: 
					final_cmp_addr.append(hex(start_addr)) 
					final_sink_addr = final_sink_addr + new_accesses 

	end = time.time() 
	elapsed = end - start 

	if len(all_accesses) != 0: 
		log("\n analysis during {}".format(elapsed)) 
		log("\n vulner_flag: 1\n") 
		sysname = e['file'] 
		callee_addr = e['call_address'] 
		caller_addr = e['caller_address'] 
		caller = e['caller_function'] 
		cmp_addr = str(final_cmp_addr) 
		sink_addr = str(final_sink_addr)  
		if not os.path.exists(DB_NAME): 
			create_static_analysis_table() 
		insert_record( 
			sysname, callee_addr, caller_addr, caller, 
			cmp_addr, sink_addr, None, None, None, None, None, None, None 
		) 
	else: 
		log("\n analysis during {}".format(elapsed)) 
		log("\n vulner_flag: 0\n") 


base_dir = ROOT_FOLDER + "binary_file\\" 
json_file = ROOT_FOLDER + "analysis_result\\clap_result\\clap_result.json" 
json_data = load_json(json_file) 

start_file_flag = 0 
start_file = "bthport.sys" 
start_callsite_flag = 0 
start_callsite = "0x140092cca"
file_entries = {} 
for callee_name, entries in json_data.items(): 
	for entry in entries: 
		if "::" in entry: 
			continue 
		try: 
			file_name, func_name, func_addr, addr = entry.split(":") 
		except: 
			print(entry) 
			input() 

		if file_name not in file_entries: 
			file_entries[file_name] = [] 
		file_entries[file_name].append((callee_name, func_name, addr, func_addr)) 

data = {} 
for file_name, entries in file_entries.items(): 
	if start_file_flag == 1: 
		if file_name != start_file: 
			print("pass {}".format(file_name)) 
			continue 
	else: 
		start_file_flag = 0 

	print("Loading file {}:".format(file_name)) 
	print("Creating project and analyzing CFG:") 
	proj = angr.Project(base_dir + file_name, auto_load_libs=False) 
	cfg = proj.analyses.CFGFast() 
	base_addr = proj.loader.main_object.min_addr
	print("Create cfg done, start analyzing")
	for callee_name, func_name, addr, func_addr in entries: 
		if start_callsite_flag == 1: 
			if start_callsite != addr: 
				print("pass {}".format(addr)) 
				continue 
		else: 
			start_callsite_flag = 0 

		print("working on {}(caller) {}(callee)".format(func_name,callee_name)) 
		res = check_block_chain_ret_with_cfg(cfg, proj, base_addr + int(addr, 16)) 
		if res == 0: 
			print(f"[-] {callee_name} directly returned, called by {func_name}, addr: {hex(base_addr + int(addr,16))}") 
			log(f"\n[-] {callee_name} directly returned, called by {func_name}, addr: {hex(base_addr + int(addr,16))}\n") 
		else: 
			data['target_function'] = callee_name # callee_name 
			data['file'] = file_name # *.sys 
			data["caller_function"] = func_name # caller_name 
			data["caller_address"] = hex(base_addr + int(func_addr,16)) # caller_addr 
			data["call_address"] = hex(base_addr + int(addr,16)) # callee_addr 
			analyze_binary(proj, cfg, data) 

def print_block_instructions(binary_path, addr): 
	proj = angr.Project(binary_path, auto_load_libs=False) 
	try: 
		block = proj.factory.block(addr) 
	except Exception as e: 
		print(f"[!] Error loading block at {hex(addr)}: {e}") 
		return 

	print(f"Disassembly at block starting from {hex(block.addr)}:") 
	for insn in block.capstone.insns: 
		print(f" {hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}") 

import angr 

def print_function_disassembly(binary_path, addr): 
	proj = angr.Project(binary_path, auto_load_libs=False) 
	print(f"[*] Building CFG for {binary_path} ...") 
	cfg = proj.analyses.CFGFast() 
	func = cfg.kb.functions.floor_func(addr) 
	if not func: 
		print(f"[!] Cannot find function containing address {hex(addr)}.") 
		return 

	print(f"\n[*] Function found: {func.name} @ {hex(func.addr)}") 
	print("=" * 60) 
	for block in func.blocks: 
		print(f"\n--- Basic block at {hex(block.addr)} ---") 
		for insn in block.capstone.insns: 
			print(f" {hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}") 
	print("=" * 60) 
	print("[*] End of function disassembly.") 


