
#coding:utf-8

import idc
import imp
import idautils 
import idaapi
import util 
import ida_auto
import ida_nalt
import ida_pro
imp.reload(util)
from util import *
from collections import defaultdict
import ida_name
import ida_loader

import importlib
import config
importlib.reload(config)
from config import *


def save_int_function(driver, function_name):
    save_file  = ROOT_FOLDER + "assert_functions.txt"
    with open(save_file,"a") as f:
        f.write(driver+" "+function_name+"\n")


def get_absolute_assert_function(file_assert_function_list):
    for _ in range(0,2):
        for func in idautils.Functions():
            name = ida_name.get_name(func)
            if check_assert(func,file_assert_function_list) == True:
                print("[+] new termintion function: {}".format(name))
                assert_name = idc.get_name(func, ida_name.GN_VISIBLE)
                if assert_name not in file_assert_function_list:
                    file_assert_function_list.append(assert_name)
                    # print(file_assert_function_list)
                    save_int_function(ida_nalt.get_root_filename(),assert_name)

def get_assert():
    # init_assert_function_list()
    file_assert_function_list = []
    file_assert_function_list = init_part_assertion_function(ida_nalt.get_root_filename())
    get_absolute_assert_function(file_assert_function_list)

# ida_auto.auto_wait()
# get_assert()
# ida_pro.qexit(0)


# get condition assert

def save_condition_int_function(driver, function_name):
    save_file  = ROOT_FOLDER + "condition_assert_functions.txt"
    with open(save_file,"a") as f:
        f.write(driver+" "+function_name+"\n")

def get_condition_assert_function(file_assert_function_list):
    for func in idautils.Functions():
        if get_function_insn_num(func) > 100:
            continue
        name = ida_name.get_name(func)
        # if "ReportViolation" not in name:
        #     continue
        # print("doing {}".format(name))
        if check_condition_assert(func,file_assert_function_list) == True:
            print("[+] new global condition termintion function: {}".format(name))
            assert_name = idc.get_name(func, ida_name.GN_VISIBLE)
            save_condition_int_function(ida_nalt.get_root_filename(),assert_name)
        if check_input_assert(func,file_assert_function_list) == True:
            print("[+] new input condition termintion function: {}".format(name))
            assert_name = idc.get_name(func, ida_name.GN_VISIBLE)
            save_condition_int_function(ida_nalt.get_root_filename(),assert_name)

def get_condition_assert():
    # init_assert_function_list()
    file_assert_function_list = []
    file_assert_function_list = init_part_assertion_function(ida_nalt.get_root_filename())
    get_condition_assert_function(file_assert_function_list)

# ida_auto.auto_wait()
get_condition_assert()
# ida_pro.qexit(0)