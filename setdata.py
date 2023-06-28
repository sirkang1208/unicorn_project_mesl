from elfparser import *
import json
import datetime

#skip log values
skip_len_i = 0

OutData = []
e_sec = []
copy_mne = []
InIdx = 0
count = 0
# reference.txt global val
refsIdx = 1
reffIdx = 0

# open script file
with open("./input.json", "r") as f:
    script_data = json.load(f)

# log file setting before the program starts
# if the log file name is not set, "%Y-%m-%d %H_%M_%S".txt is created.
try:
    filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + " " + script_data["files"]["log_file_name"] + ".txt"
except:
    filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + ".txt" 

elf_file_name = script_data["files"]["elf_file_path"]

# making elf loader object for setup address
e = ElfLoader(elf_file_name)
f_list = e.func_list
func_list = e.check_list(f_list)

#get section data
e_s = e.section_list_make()
e_sec = e.check_list(e_s)

# code update start address
ADDRESS = e.get_start_add(e_sec)

# exit addr -> set lr register at the beginning
exit_addr = e.get_func_address('exit')

# _exit addr
exit_addr_real = e.get_func_address('_exit')

# memory address where emulation starts
emu_ADDRESS = e.get_func_address('main')

# emulation length -> main function length is enough
main_func_length = e.get_main_len()

# emulation finish address
finish_ADDRESS = emu_ADDRESS + main_func_length

# code which gonna be emulated
ARM_CODE = e.get_code(ADDRESS)


#output addr and length addr
OutData_addr,length_addr = e.output_symbol_data_get()

        