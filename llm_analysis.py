import importlib
import database
importlib.reload(database)
import call_api
importlib.reload(call_api)
from call_api import do_request_series, get_from_response
from database import *
# from helper.dao import * 
import yaml
import re
import logging
# from ask import _read_prompt_file
# from rich.progress import track

import importlib
import config
importlib.reload(config)
from config import *

def _read_prompt_file():
    with open(prompt_file, "r") as f:
        prompts = yaml.safe_load(f)
    return prompts




def run_with_majority_voting(prompts, task, model, temperature, max_tokens, xml_tag, case_id, max_iters):
    res_count = {}
    one_more_iter = True
    failed_before = False
    abs_majority = max_iters // 2 + 1
    
    
    for _ in range(max_iters):
        msg = do_request_series(model, temperature, max_tokens, prompts, task)
        if msg is None:
            if failed_before:
                return None
            failed_before = True
            continue
        
        response = msg[-1]['content']
        res = get_from_response(response, xml_tag)
        if res:
            if res in res_count:
                res_count[res] += 1
            else:
                res_count[res] = 1
        else:
            continue
        
        
        if res == "uncertain" and one_more_iter:
            max_iters += 1
            one_more_iter = False
        
        if res_count and max(res_count.values()) >= abs_majority:
            break
        
    # find the most common result
    return max(res_count, key=res_count.get) if res_count else None


def supplement_structure_info(record_dict, model, temperature=1.0, max_tokens=2048, max_iters=1):
    PROMPT = _read_prompt_file()
    prompts = PROMPT['supplement_structure_info']
    task = {"id": "var_name", "sys_file": record_dict["sysname"],
            "case_id": record_dict["id"], "context": record_dict}
    res = run_with_majority_voting(
        prompts, task, model, temperature, max_tokens, 'inferences', task['case_id'], max_iters)
    insert_llm_result(None, None, None, res, record_id = record_dict["id"], db_name=DB_NAME)


def infer_variable_name_llm(record_dict, model, temperature=1.0, max_tokens=2048, max_iters=1):
    PROMPT = _read_prompt_file()
    prompts = PROMPT['infer_variable_name']
    task = {"id": "var_name", "sys_file": record_dict["sysname"],
            "case_id": record_dict["id"], "context": record_dict}
    res = run_with_majority_voting(
        prompts, task, model, temperature, max_tokens, 'infer_res', task['case_id'], max_iters)
    if res:
        tainted_var = get_from_response(res, "tainted_var")
        sink = get_from_response(res, "sink")
        sink_lineno = get_from_response(res, "sink_lineno")
        cmp_ = get_from_response(res, "cmp")
        cmp_lineno = get_from_response(res, "cmp_lineno")
        callsite = get_from_response(res, "callsite")
        callsite_lineno = get_from_response(res, "callsite_lineno")
        record_id = record_dict["id"]
        update_infer_result(record_id, tainted_var, sink, sink_lineno, cmp_, cmp_lineno, callsite, callsite_lineno, db_name=DB_NAME)
    else:
        logging.error(
            f"Failed to infer variable name for {task['case_id']}")






def smart_bug_analysis_llm(record_dict, model, temperature=1.0, max_tokens=2048, max_iters=1):
    PROMPT = _read_prompt_file()
    prompts = PROMPT['smart_bug_analysis']

    task = {"id": "var_name", "sys_file": record_dict["sysname"],
            "case_id": record_dict["id"], "context": record_dict}
    res = run_with_majority_voting(
        prompts, task, model, temperature, max_tokens, 'bug_eval', task['case_id'], max_iters)
    if res:
        insert_llm_result(None,None,None,record_id=record_dict["id"])
        update_secA(record_dict["id"], res, db_name = DB_NAME)
    else:
        logging.error(
            f"Failed to infer analysis for {task['case_id']}")   
    print("done")
            
def __is_false_alarm_by_analysis(record_id):
    ana_res = fetch_llm_by_id(record_id, db_name=DB_NAME)
    if ana_res is None:
        return True
    return 'not_a_bug' in ana_res
    
def sanitizer_detection_llm(record_dict, model, temperature=1.0, max_tokens=2048, max_iters=1):
    sanitizer_detection(record_dict, model, temperature=1.0, max_tokens=2048, max_iters=1)
    
    
def sanitizer_detection(record_dict, model, temperature=1.0, max_tokens=2048, max_iters=1):
    PROMPT = _read_prompt_file()
    prompts = PROMPT['sanitizer_detection']

    # filter: if "smart bug analysis" is not a bug
    if __is_false_alarm_by_analysis(record_dict["id"]):
        return 

    task = {"id": "var_name", "sys_file": record_dict["sysname"],
            "case_id": record_dict["id"], "context": record_dict}
    res = run_with_majority_voting(prompts, task, model, temperature, max_tokens, 'final_res', task['case_id'], max_iters)
    # if res:
    #     update_conclusion(task['case_id'], res, model)
    # else:
    #     update_conclusion(task['case_id'], "error", model)
    #     logging.error(
    #         f"Failed to infer analysis for {task['case_id']}")
