from __future__ import print_function
from unicorn import *
from capstone import *
from xprint import to_hex, to_x_32
from unicorn.arm_const import *
from elfloader import *
from scenario import *
from uprint import *
#import clock
import sys

REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}

# log file setting before the program starts
name = input("please input log file name : ")
e_name = input("please input elf file name : ")
# or get name from text file

filename = "./log/" + name + ".txt"
elf_file_name = e_name

# making elf loader object for setup address
e = ElfLoader(elf_file_name) 

#get section data
e_sec = []
e_sec = e.section_list_make()

# code update start address
ADDRESS = e.get_start_add()

# memory address where emulation starts
emu_ADDRESS = e.get_func_address('main')

# emulation length -> main function length is enough
main_func_length = e.get_main_len()

# exit addr -> set lr register at the beginning
exit_addr = e.get_func_address('exit')

# _exit addr
exit_addr_real = e.get_func_address('_exit')

# board dependent data, must be set before the emulation
STACK_ADDRESS = 0x80000000
STACK_SIZE = 0x10000

with open(elf_file_name, "rb") as f:
    f.seek(ADDRESS,0)
    code = f.read()

# code which gonna be emulated
ARM_CODE = code

section_insn = []
copy_mne = []
InIdx = 0
count = 0

# make_insn_array(ARM_CODE,ADDRESS)
def make_insn_array(input,addr):
    global InIdx
    global count
    # Initialize Capstone in ARM mode
    mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    # prev setting of disassemble
    mc.syntax = None
    mc.detail = True

    # idx : index of array which contains information about intruction
    # copy_mne : array that stores mnemonic data copied

    # copy mnemonics to copy_mne
    # add modified register at copy_mne
    for insn in mc.disasm(input, addr):
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
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

# hook every instruction and fetch information we need
def code_hook(uc, address, size, user_data):
    #input result in .txt file
    temp = sys.stdout
    sys.stdout = open(filename,'a')

    addr = int((address-ADDRESS)/4)
    print("instruction :", user_data[addr][0],end=' ')
    print("/ register data :", end="")
    print_all_reg(uc)
    print("/ modified register : ", end ='')
    print(user_data[addr][1:], end = ' ')
    print_mem(uc,address,4)
    # print("/ clock count: ", clock.cycle_cal(user_data[addr][0]))

    sys.stdout = temp

    if address == exit_addr_real:
        uc.emu_stop()

#scenario hook
def scene_hook(uc,address,size, user_data):
    for i in range(len(user_data)):
        if user_data[i][0] == address:
            print("address : ", end = "")
            print(address)
            select_scenario(uc,address, user_data[i][1],user_data[i][2])

# function_skip
# def test_hook(uc,b,c,d):
#     uc.reg_write(REG["pc"], 33404)
#     함수값 보존하고 싶을 땐 점프 전 r0값 저장해뒀다가 reg_write(r0)로 작성

def main():

    print("Emulate ARM code")

    try:
        # Initialize Unicorn in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 4*1024*1024)
        mu.mem_map(0x0,1024)
        # map stack region as much as stack size
        mu.mem_map(STACK_ADDRESS - STACK_SIZE, STACK_SIZE)

        for i in range(len(e_sec)):
            # read file from start address to eof
            with open(elf_file_name, "rb") as f:
                f.seek(e_sec[i][1],0)
                cod = f.read(e_sec[i][2])

            if e_sec[i][0] != 0:
                mu.mem_write(e_sec[i][0],cod)
            else:
                mu.mem_write(e_sec[i][1],cod)            

        # initialize machine registers
        # stack pointer must be initialized
        mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_FP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_LR, exit_addr)

        # make copy_mne list until eof
        reccod = code
        recaddr = ADDRESS
        while len(copy_mne)/int(len(ARM_CODE)/4) < 0.99:
            reccod, recaddr = make_insn_array(reccod,recaddr)

        se_input = []
        if len(se_input) == 0:
            pass
        else :
            mu.hook_add(UC_HOOK_CODE, scene_hook, se_input, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))
        
        # function_skip
        # mu.hook_add(UC_HOOK_CODE, test_hook, copy_mne, begin= func_test, end=func_test + 52)

        mu.hook_add(UC_HOOK_CODE, code_hook, copy_mne, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))
        
        # add address should be same as main function length
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_func_length)

        print(">>> Emulation done. Below is the CPU context")

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()