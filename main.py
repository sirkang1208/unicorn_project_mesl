from __future__ import print_function
from unicorn import *
from capstone import *
from capstone.arm import *
from xprint import to_hex, to_x_32
from unicorn.arm_const import *
import sys
import datetime
import lief
import operator

elf_file = lief.parse("./Unicorn_development_source/compiled_program/toy_example")
functions = {}

try:
    for f in elf_file.exported_functions:
        tmpn = f.name
        c = 0
        while tmpn in functions:
            c += 1
            tmpn = f.name + str(c)
        functions[tmpn] = f.address
except:
    pass

d1 = sorted(functions.items(), key = lambda x : x[1] )
func_sort = dict(d1)

for index, (key,elem) in enumerate(func_sort.items()):
    if key == 'main':
        a = index
        break
func_list = list(func_sort.items())

# code update start address
ADDRESS = list(func_sort.values())[0]
print(ADDRESS)

# memory address where emulation starts
emu_ADDRESS = func_sort.get('main')
print(emu_ADDRESS)

# emluation length -> main function length is enough
main_func_length = func_list[a+1][1] - emu_ADDRESS
print(main_func_length)

# exit addr -> set lr register at the beginning
exit_addr = hex(func_sort.get('exit'))

# read file from start address to eof
with open("./Unicorn_development_source/compiled_program/toy_example", "rb") as f:
    f.seek(int(str(ADDRESS),0))
    code = f.read()

# code which gonna be emulated
ARM_CODE32 = code

# board dependent data, must be set before the emulation
STACK_ADDRESS = 0x80000000
STACK_SIZE = 0x10000

# log file setting before the program starts
filename = "./log/" + datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S") + ".txt"

# print instruction detail -> address: instruction opcode string
def print_insn_detail(insn):
    # print address, mnemonic and operands
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

    if insn.id == 0:
        return
    
    (regs_read, regs_write) = insn.regs_access()

    if len(regs_read) > 0:
        print("\tRegisters read:", end="")
        for r in regs_read:
            print(" %s" %(insn.reg_name(r)), end="")
        print()

    if len(regs_write) > 0:
        print("\tRegisters modified:", end="")
        for r in regs_write:
            print(" %s" %(insn.reg_name(r)), end="")
        print()

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

# select function
def select_func(uc,a):
    if a == 'r':
        change_reg(uc)
    elif a == 'm':
        change_mem(uc)
    elif a == 'rv':
        print_all_reg(uc)
    elif a == 'mv':
        print_mem(uc)
    elif a == 'p':
        pass

# TODO change memory
def change_mem(uc,a):
    addr = input("input address : ")

# change register by command / ex) 10 1000 -> r10's data change into 1000
def change_reg(uc):
    r_num = input('register number : ')
    REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}.get(r_num, "알 수 없는")
    if REG == "알 수 없는":
        print("wrong register number")
        return
    data = input('data : ')
    uc.reg_write(REG,int(data))

# hook every instruction and fetch information we need
def hook_code(uc, address, size, user_data):
    #input result in .txt file
    addr = int((address-ADDRESS)/4)
    print("instruction :", user_data[addr][0],end=' ')
    print("/ register data :", end="")
    print_all_reg(uc)
    print("/ modified register : ", end ='')
    print(user_data[addr][1:], end = ' ')
    print_mem(uc,address,4)

def main():

    print("Emulate ARM code")

    # save the log file
    temp = sys.stdout
    sys.stdout = open(filename,'a')

    try:
        # Initialize Unicorn in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        
        # Initialize Capstone in ARM mode
        mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 4*1024*1024)
        
        # map stack region as much as stack size
        mu.mem_map(STACK_ADDRESS - STACK_SIZE, STACK_SIZE)


        # write machine code which should be emulated to memory
        mu.mem_write(ADDRESS, ARM_CODE32)

        # initialize machine registers
        # stack pointer must be initialized
        mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
        
        # idx : index of array which contains information about intruction
        # copy_mne : array that stores mnemonic data copied
        idx = 0
        copy_mne = []
        # print("*" * 16)
        # print("Platform: ARM")
        # print("Code: %s" % to_hex(ARM_CODE32))
        # print("Disasm:")
        
        # prev setting of disassemble
        mc.syntax = None
        mc.detail = True

        # copy mnemonics to copy_mne
        # add modified register at copy_mne
        for insn in mc.disasm(ARM_CODE32, 0x10000):
            line = []
            copy_mne.append(line)
            copy_mne[idx].append(insn.mnemonic)
            (regiread,regiwrite) = insn.regs_access()
            for r in regiwrite:
                copy_mne[idx].append(insn.reg_name(r))
            # print_insn_detail(insn)
            # print ()
            idx += 1
        
        # trace every instruction hook
        mu.hook_add(UC_HOOK_CODE, hook_code, copy_mne, begin= ADDRESS, end= ADDRESS + len(ARM_CODE32))

        # add address should be same as main function length
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_func_length)
        
        sys.stdout = temp

        # TODO error occurs because of return 0; -> no information about return 0 address
        print(">>> Emulation done. Below is the CPU context")

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()
