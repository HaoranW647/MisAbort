import idaapi
import idautils
import idc
import importlib
from ida_api import *
import yaml
import idaapi
import database
importlib.reload(database)
from database import *
import llm_analysis
importlib.reload(llm_analysis)
from llm_analysis import infer_variable_name_llm, supplement_structure_info, smart_bug_analysis_llm, sanitizer_detection_llm

import importlib
import config
importlib.reload(config)
from config import *



COLUMNS = [
    "id", "sysname", "callee_addr", "caller_addr", "caller",
    "cmp_addr", "sink_addr", "taint_v",
    "cmp_pscode", "cmp_lineno",
    "sink_pscode", "sink_lineno",
    "callee_pscode", "callee_lineno"
]


def _read_prompt_file():
    with open(prompt_file, "r") as f:
        prompts = yaml.safe_load(f)
    return prompts



def fetch_records_for_current_file():
    sysname = idaapi.get_root_filename()
    results = fetch_by_sysname(sysname,db_name=DB_NAME)
    if results:
        print(f"Found {len(results)} record(s) for driver file: {sysname}\n")
        for row in results:
            record_dict = {col: val for col, val in zip(COLUMNS, row) if val is not None}
            for k, v in record_dict.items():
                print(f"{k}: {v}")
            print("-" * 40)
    else:
        print(f"No records found for driver file: {sysname}")



# model = "Pro/deepseek-ai/DeepSeek-V3"
model = "gpt-4.1"
max_iters = 1

cur_file = idaapi.get_root_filename()


# update information
ida_auto.auto_wait()
# record_dict = fetch_by_sysname(cur_file, db_name = DB_NAME)
# for record in record_dict:
#     # print("doing ... {}".format(str(record)))
#     supplement_structure_info(record, model=model, max_iters=max_iters)
#     infer_variable_name_llm(record, model=model, max_iters=max_iters)


# # fetch again 
record_dict = fetch_by_sysname(cur_file, db_name = DB_NAME)
for record in record_dict:
    if record["sink_pscode"]:
        if "return" in record["sink_pscode"]:
            continue
    if record["cmp_pscode"] == None:
        continue
    print("doing {} ...".format(record["id"]))
    smart_bug_analysis_llm(record, model=model, max_iters=max_iters)
    sanitizer_detection_llm(record, model=model, max_iters=max_iters)

ida_pro.qexit(0)







