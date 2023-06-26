from __future__ import print_function
from unicorn import *
from capstone import *
from unicorn.arm_const import *
from elfloader import *
from uprint import *
#import clock
import sys
import json
import datetime

REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}

with open("./input.json", "r") as f:
    script_data = json.load(f)

try:
    filename = "./log/" + script_data["Files"]["log_file_name"]
except:
    filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + ".txt" 

elf_file_name = script_data["Files"]["elf_file_path"]

e = ElfLoader(elf_file_name) 

e_sec = []
e_sec = e.section_list_make()

ADDRESS = e.get_start_add()

emu_ADDRESS = e.get_func_address('main')

main_func_length = e.get_main_len()

exit_addr = e.get_func_address('exit')

exit_addr_real = e.get_func_address('_exit')

STACK_ADDRESS = 0x80000000
STACK_SIZE = 0x10000

with open(elf_file_name, "rb") as f:
    f.seek(ADDRESS,0)
    code = f.read()

ARM_CODE = code

section_insn = []
copy_mne = []
InIdx = 0
count = 0

def make_insn_array(input,addr):
    global InIdx, count

    mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    mc.syntax = None
    mc.detail = True

    for insn in mc.disasm(input, addr):
        line = []
        copy_mne.append(line)
        copy_mne[InIdx].append(insn.mnemonic)
        (regiread,regi_write) = insn.regs_access()
        for r in regi_write:
            copy_mne[InIdx].append(insn.reg_name(r))
        InIdx += 1

    if len(copy_mne)/int(len(ARM_CODE)/4) < 1:
        count += 1
        line = []
        copy_mne.append(line)
        copy_mne[InIdx].append("NONE")
        InIdx += 1
        retaddr = ADDRESS+InIdx*4
        with open(elf_file_name, "rb") as f:
            f.seek(ADDRESS+InIdx*4,0)
            fcode = f.read()
        
        return fcode, retaddr
    else:
        return 0, addr

def write_log(uc, address, user_data, line_count):

    temp = sys.stdout
    addr = int((address-ADDRESS)/4)
    print("[" + str(line_count) + "]", end=' ')
    print("instruction :", user_data[addr][0],end=' ')
    print("/ register data :", end="")
    print_all_reg(uc)
    print("/ modified register : ", end ='')
    print(user_data[addr][1:], end = ' ')
    print_mem(uc,address,4)
    sys.stdout = temp

def code_hook(uc, address, size, user_data):
    temp = sys.stdout
    sys.stdout = open(filename,'a')

    write_log(uc, address, user_data, hex(address))

    sys.stdout = temp

    if address == exit_addr_real:
        uc.emu_stop()

def main():

    print("Emulating the code...")

    try:
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        mu.mem_map(ADDRESS, 4*1024*1024)
        mu.mem_map(0x0,1024)
        mu.mem_map(STACK_ADDRESS - STACK_SIZE, STACK_SIZE)

        for i in range(len(e_sec)):
            with open(elf_file_name, "rb") as f:
                f.seek(e_sec[i][1],0)
                cod = f.read(e_sec[i][2])

            if e_sec[i][0] != 0:
                mu.mem_write(e_sec[i][0],cod)
            else:
                mu.mem_write(e_sec[i][1],cod)            

        mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_FP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_LR, exit_addr)

        reccod = code
        recaddr = ADDRESS
        while len(copy_mne)/int(len(ARM_CODE)/4) < 0.99:
            reccod, recaddr = make_insn_array(reccod,recaddr)

        mu.hook_add(UC_HOOK_CODE, code_hook, copy_mne, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))
        
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_func_length)

        print(">>> Emulation done. Below is the CPU context")

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()