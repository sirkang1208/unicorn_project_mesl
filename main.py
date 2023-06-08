from __future__ import print_function
from unicorn import *
from capstone import *
from xprint import to_hex, to_x_32
from unicorn.arm_const import *
from elfloader import *
from scenario import *
#import clock
import sys
import datetime
import random
import operator

REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}

# log file setting before the program starts
filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + ".txt"
elf_file_name = "./Unicorn_development_source/compiled_program/arm-none_compiled_1"

# making elf loader object for setup address
e = ElfLoader(elf_file_name) 

# function_skip
# func_test = e.get_func_address('add')


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

# read file from start address to eof
with open(elf_file_name, "rb") as f:
    f.seek(ADDRESS,0)
    code = f.read()

# code which gonna be emulated
ARM_CODE = code

# board dependent data, must be set before the emulation
STACK_ADDRESS = 0x80000000
STACK_SIZE = 0x10000

copy_mne = []

def make_insn_array():
    # Initialize Capstone in ARM mode
    mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    # prev setting of disassemble
    mc.syntax = None
    mc.detail = True

    # idx : index of array which contains information about intruction
    # copy_mne : array that stores mnemonic data copied
    idx = 0

    # copy mnemonics to copy_mne
    # add modified register at copy_mne
    for insn in mc.disasm(ARM_CODE, ADDRESS):
        #print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        line = []
        copy_mne.append(line)
        copy_mne[idx].append(insn.mnemonic)
        (regiread,regi_write) = insn.regs_access()
        for r in regi_write:
            copy_mne[idx].append(insn.reg_name(r))
        idx += 1
    # trace every instruction hook
    print(len(copy_mne), end = ' / ')
    print(int(len(ARM_CODE)/4))
    
# print all register
def print_all_reg(uc):
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    r6 = uc.reg_read(UC_ARM_REG_R6)
    r7 = uc.reg_read(UC_ARM_REG_R7)
    r8 = uc.reg_read(UC_ARM_REG_R8)
    r9 = uc.reg_read(UC_ARM_REG_R9)
    r10 = uc.reg_read(UC_ARM_REG_R10)
    fp = uc.reg_read(UC_ARM_REG_FP)
    ip = uc.reg_read(UC_ARM_REG_IP)
    sp = uc.reg_read(UC_ARM_REG_SP)
    lr = uc.reg_read(UC_ARM_REG_LR)
    pc = uc.reg_read(UC_ARM_REG_PC)
    cpsr = uc.reg_read(UC_ARM_REG_CPSR)
    
    print("R0 = 0x%x" %r0, end = ', ')
    print("R1 = 0x%x" %r1, end = ', ')
    print("R2 = 0x%x" %r2, end = ', ')
    print("R3 = 0x%x" %r3, end = ', ')
    print("R4 = 0x%x" %r4, end = ', ')
    print("R5 = 0x%x" %r5, end = ', ')
    print("R6 = 0x%x" %r6, end = ', ')
    print("R7 = 0x%x" %r7, end = ', ')
    print("R8 = 0x%x" %r8, end = ', ')
    print("R9 = 0x%x" %r9, end = ', ')
    print("R10 = 0x%x" %r10, end = ', ')
    print("FP = 0x%x" %fp, end = ', ')
    print("IP = 0x%x" %ip, end = ', ')
    print("SP = 0x%x" %sp, end = ', ')
    print("LR = 0x%x" %lr, end = ', ')
    print("PC = 0x%x" %pc, end = ', ')
    print("CPSR = 0x%x" %cpsr, end = ' ')

# print 'len' length memory at 'addr' address
def print_mem(uc,addr, m_len):
    tot_mem = uc.mem_read(addr,m_len)
    print("/ memory data : ", end = "")
    for i in range(len(tot_mem)):
        print("\\x%x" %tot_mem[i], end = "")
    print()

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

def scene_hook(uc,address,size, user_data):
    if user_data[1] == address:
        print("address : ", end = "")
        print(address)
        select_scenario(uc,address, user_data[0])

# skip instruction
def skip_insn_hook(uc, address,size, user_data):
    if copy_mne[int((address-ADDRESS)/4)][0] == user_data[1]:
        pc_data = uc.reg_read(UC_ARM_REG_PC)
        uc.reg_write(REG["pc"],pc_data+4)

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


        # write machine code which should be emulated to memory
        mu.mem_write(ADDRESS, ARM_CODE)

        # initialize machine registers
        # stack pointer must be initialized
        mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_FP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_LR, exit_addr)

        make_insn_array()

        se_input = []
        print_selection()
        command = input("select the senario : ")
        se_input.append(command)
        if se_input[0] == 's':
            user_insn = input("input skip instruction : ")
            se_input.append(user_insn)
            mu.hook_add(UC_HOOK_CODE, skip_insn_hook, se_input, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))
        else:
            set_addr = input("set senario start address :")
            se_input.append(int(set_addr))
            mu.hook_add(UC_HOOK_CODE, scene_hook, se_input, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))
        
        # function_skip
        # mu.hook_add(UC_HOOK_CODE, test_hook, copy_mne, begin= func_test, end=func_test + 52)

        mu.hook_add(UC_HOOK_CODE, code_hook, copy_mne, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))

        # save the log file


        # add address should be same as main function length
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_func_length)


        # TODO error occurs because of return 0; -> no information about return 0 address
        print(">>> Emulation done. Below is the CPU context")

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()