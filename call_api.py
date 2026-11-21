import logging
from time import sleep
import openai
import os
import re

import xml.etree.ElementTree as ET

import importlib
import ida_api
importlib.reload(ida_api)
import database
importlib.reload(database)
from database import *
import ida_api as ia

import importlib
import config
importlib.reload(config)
from config import *

__CALLBACK_ITER_MAX_LIMIT = 15
__API_RETRY_LIMIT = 3
__RETRY_TIMEOUT = [60, 120, 300]

api_key = "api_key_here"

log_dir = ROOT_FOLDER


def get_task_logger(case_id):
    logger = logging.getLogger(f"task_{case_id}")
    logger.setLevel(logging.INFO)

    if logger.hasHandlers():
        logger.handlers.clear()


    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(ch)

    fh = logging.FileHandler(f"{log_dir}\\log\\llm\\{case_id}.log", mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(fh)

    return logger

def get_from_response(response, xml_tag='response'):
    pattern = f'<{xml_tag}>(.*?)</{xml_tag}>'
    match = re.search(pattern, response, re.DOTALL)
    if match:
        return match.group(1).strip()
    else:
        return None


def get_request_list(response):
    response = f"<root>{response}</root>"
    try:
        root = ET.fromstring(response)
        request_list = []
        for req in root.findall('request'):
            req_name = req.find('name').text
            args_elem = req.find('args').findall('arg')
            args = [arg.text for arg in args_elem]
            request_list.append({'name': req_name, 'args': args})

        return request_list

    except Exception as e:
        logging.error(e)
        return []


def safe_get_first(lst):
    if lst:
        return lst[0]
    return None



ARGS_MAP = {
    'get_pseudocode_by_func': lambda task: ia.get_pseudocode_by_func(int(task['context']['caller_addr'],16)),
    'get_disasm_by_func': lambda task: ia.get_disasm_by_func(int(task['context']['caller_addr'],16)),
    'get_cmp_addr': lambda task: ia.get_cmp_addr(task),
    'get_sink_addr': lambda task: ia.get_sink_addr(task),
    'get_callsite_addr': lambda task: ia.get_callsite_addr(task),
    'get_taint_variable': lambda task: ia.get_taint_variable(task),
    'get_cmp': lambda task: ia.get_cmp(task),
    'get_cmp_loc': lambda task: ia.get_cmp_loc(task),
    'get_callee_code': lambda task: ia.get_callee_code(task),
    'get_callee_code_loc': lambda task: ia.get_callee_code_loc(task),
    'get_sink': lambda task: ia.get_sink(task),
    'get_sink_loc': lambda task: ia.get_sink_loc(task),
    'get_driver': lambda task: ia.get_driver(task),
    'get_analysis_result': lambda task: ia.get_analysis_result(task),
    'get_callsite_context': lambda task: ia.get_callsite_context(task),
    'get_inference': lambda task: ia.get_inference(task),
}

CALLBACKS = {
    'need_func_def': lambda task, arg: ia.need_func_def(task, arg),
    'need_caller': lambda task, arg: ia.need_caller(task, arg),
}






def _do_request(model, temperature, max_tokens, formatted_messages, _retry=0, last_emsg=None):
    sleep(0.2)  # avoid rate limit

    try:
        client = openai.OpenAI(api_key=api_key)

        completion = client.chat.completions.create(
            model=model,
            messages=formatted_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=False
        )


    except Exception as e:
        logging.error(e)
        

    return completion.choices[0].message.content



def __is_failed(response):
    return response.startswith('{"ret": "failed"')


def do_request_llm(model, temperature, max_tokens, formatted_messages, cur_prompt, round='N/A', case_id='N/A'):
    # formatted_messages.append({"role": "system", "content": cur_prompt})
    response = _do_request(model, temperature, max_tokens, formatted_messages)
    logger = get_task_logger(case_id)
    logger.info(f"Round: {round}, Case {case_id}, Response: {response}")
    # logging.info(f"Round: {round}, Case {case_id}, Response: {response}")
    return response


def get_params(args, task):
    res = []
    for arg in args:
        if arg in ARGS_MAP:

            ret = ARGS_MAP[arg](task)
            res.append(ret)
        else:
            raise ValueError(f"Unknown arg: {arg}")
    return res


def do_request_series(model, temperature, max_tokens, prompts, task):
    formatted_messages = []
    task_id = task['id']
    case_id = task['case_id']
    task['model'] = model
    # cb.clear_counter()

    # prompts[0] = prompts[0].format(**init_info)
    for index, cur_prompt in enumerate(prompts):
        if task_id != 'N/A':
            round = 'Task ' + task_id + ' - ' + str(index + 1)
        else:
            round = 'N/A'
        if 'args' in cur_prompt:
            params = get_params(cur_prompt['args'], task)

            if params is None:
                logging.error(f"Failed to get params for {cur_prompt['args']}")
                return None
            prompt = cur_prompt['text'].format(*params)
        else:
            prompt = cur_prompt['text']
        # handle callbacks
        for cb_iter in range(__CALLBACK_ITER_MAX_LIMIT):
            formatted_messages.append({"role": "user", "content": prompt})      
            ret = do_request_llm(model, temperature, max_tokens,
                                 formatted_messages, prompt, round, case_id)
            formatted_messages.append({"role": "assistant", "content": ret})

            if __is_failed(ret):
                return None

            call_back_finished = True

            # construct the new prompt for the next iteration
            prompt = ""
            if 'record' in cur_prompt:
                record_target = cur_prompt['record']
                if record_target[0] == "conA":
                    llm_result = get_from_response(ret, record_target[0])
                    if llm_result is not None:
                        update_conA(case_id,str(llm_result),db_name = DB_NAME)
                elif record_target[0] == "conclusion":
                    llm_result = get_from_response(ret, "final_res")
                    if llm_result is not None:
                        update_conclusion(case_id,str(llm_result),db_name = DB_NAME)


            if 'callback' in cur_prompt:

                # Update: now get the list of requests from the response
                requests_body = get_from_response(ret, 'requests')

                if requests_body:
                    request_list = get_request_list(requests_body)
                    if not request_list:
                        logging.error(
                            "Failed to parse request list from response.")
                        # tells LLM we don't understand the request
                        call_back_finished = False
                        prompt = "I don't understand your request, please request as the format\n"

                    for request in request_list:
                        callback = request['name']
                        if callback in CALLBACKS:
                            response = CALLBACKS[callback](task, request['args'])
                            call_back_finished = False
                            prompt += response
                        else:
                            logging.error(
                                "Callback function {} not found.".format(callback))
                            break

            round = 'Task ' + task_id + ' - ' + \
                str(index + 1) + " - callback - " + str(cb_iter + 1)
            if call_back_finished:
                break

    return formatted_messages
