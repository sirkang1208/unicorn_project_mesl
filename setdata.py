from elfparser import *
import cycle
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
refsIdx = 0
reffIdx = 0

# arch and instruction set for clock count
clock = cycle.ARM("Cortex-M4",1,1,3)

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
func_list = e.func_list

# code update start address
ADDRESS = e.get_start_add()

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

#get section data
e_sec = e.section_list_make()
print(e_sec)

#output addr and length addr
OutData_addr,length_addr = e.output_symbol_data_get()

        