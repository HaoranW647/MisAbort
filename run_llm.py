import os
import subprocess
import shutil

import importlib
import config
importlib.reload(config)
from config import *

from time import sleep

IDA_PATH = IDA_PATH
root_folder = ROOT_FOLDER
binary_path = Binary_Path
continue_file = "srv.sys"
continue_script = True



def process_files():
    continue_flag = 1
    if continue_script == True:
        continue_flag = 0
    files = os.listdir(binary_path)
    for file in files:
        if file.lower().endswith(".sys") or file.lower().endswith(".exe"):
            if file == continue_file:
                continue_flag = 1
            if continue_flag == 1:
                file_path = os.path.join(binary_path, file)
                print("=" * 50)
                print(f"Processing {file_path} ...")
                print("=" * 50)

                s1 = f'"{IDA_PATH}" -A -S"{root_folder}LLM_based_bug_assessment.py" "{file_path}"'
                print(s1)
                try:
                    subprocess.run(s1, shell=True, timeout=18000)
                except subprocess.TimeoutExpired:
                    print(f"[!] IDA timeout on {file}\n")
                    continue


                print(f"[+] File {file} completed.\n")
                sleep(1)

if __name__ == "__main__":
    process_files()
