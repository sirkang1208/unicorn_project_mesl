from __future__ import print_function
from unicorn import *
from capstone import *
from xprint import to_hex, to_x_32
from unicorn.arm_const import *
from elfloader import *
#import clock
import sys
import datetime
import random
import operator

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
print("emu_ADDRESS: ", emu_ADDRESS)

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

# select function
def select_senario(uc,cmd,user_data,address):
    if cmd == 'p':
        pass
    elif cmd == 's':
        userInsn = input("input instruction : ")
        skip_insn(uc,user_data,address, userInsn)
    elif cmd == 'r':
        change_reg(uc)  
    elif cmd == 'set':
        s_range = input("input modify range : ")
        set_mem(uc,address,s_range)
    elif cmd == 'clr':
        c_range = input("input modify range : ")
        clr_mem(uc,address,c_range)
    elif cmd == 'bf':
        b_range = input("input modify range : ")
        bit_flip(uc,address,b_range)
    elif cmd == 'rand':
        r_range = input("input modify range : ")
        rand_mem(uc,address,r_range)
    else:
        print("wrong input, please enter again")
        select_senario(uc,cmd,user_data,address)
    

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

# TODO change memory
def change_mem(uc, data):
    addr = input("input address : ")
    uc.mem_write(addr,data)

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


REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}



# hook eveLry instruction and fetch information we need
def hook_code(uc, address, size, user_data):
    #input result in .txt file
    addr = int((address-ADDRESS)/4)
    print("instruction :", user_data[addr][0],end=' ')
    print("/ register data :", end="")
    print_all_reg(uc)
    print("/ modified register : ", end ='')
    print(user_data[addr][1:], end = ' ')
<<<<<<< HEAD
    print_mem(uc,address,4)
    print("/ clock count: ", clock.cycle_cal(user_data[addr][0]))

# function_skip
# def test_hook(uc,b,c,d):
#     uc.reg_write(REG["pc"], 33404)
#     함수값 보존하고 싶을 땐 점프 전 r0값 저장해뒀다가 reg_write(r0)로 작성
=======
    print_mem(uc,address,2)

    if address == exit_addr_real:
        uc.emu_stop()

# skip instruction
def skip_insn(uc, user_data, address, userInsn):
    if user_data[int((address-ADDRESS)/4)][0] == userInsn:
        address += 4

# set all data 1
def set_mem(uc, address,s_range):
    for i in range(s_range/4):
        uc.mem_write(address+i*4, b'\xff\xff\xff\xff')

# set all data 0
def clr_mem(uc, address,c_range):
    for i in range(c_range/4):
        uc.mem_write(address+i*4, b'\x00\x00\x00\x00')


# set all data bit_flip
def bit_flip(uc, address,b_range):
    for i in range(b_range/4):
        x = uc.mem_read(address + i*4)
        cvrt_x = int.from_bytes(x, byteorder='little')
        cvrt_x = 0xFFFFFFFF - cvrt_x
        res_x = cvrt_x.to_bytes(4,"little")
        uc.mem_write(address+i*4, res_x)

# set data random
def rand_mem(uc, address,r_range):
    for i in range(r_range/4):
        x = random.randint(0,0xFFFFFFFF)
        res_x = x.to_bytes(4,'little')
        uc.mem_write(address+i*4,res_x)


>>>>>>> 8d7083f2bf8eb137394640ea71dd76eee247611d

def main():

    print("Emulate ARM code")

    try:
        # Initialize Unicorn in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        
        # Initialize Capstone in ARM mode
        mc = Cs(CS_ARCH_ARM, CS_MODE_ARM)

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

        # print("*" * 16)
        # print("Platform: ARM")
        # print("Code: %s" % to_hex(ARM_CODE32))
        # print("Disasm:")
        
        # prev setting of disassemble
        mc.syntax = None
        mc.detail = True

        # idx : index of array which contains information about intruction
        # copy_mne : array that stores mnemonic data copied
        idx = 0
        copy_mne = []

        # copy mnemonics to copy_mne
        # add modified register at copy_mne
        for insn in mc.disasm(ARM_CODE, ADDRESS):
            print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
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

        # function_skip
        # mu.hook_add(UC_HOOK_CODE, test_hook, copy_mne, begin= func_test, end=func_test + 52)

<<<<<<< HEAD
        mu.hook_add(UC_HOOK_CODE, hook_code, copy_mne, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))
        
=======
        # save the log file
        temp = sys.stdout
        sys.stdout = open(filename,'a')

>>>>>>> 8d7083f2bf8eb137394640ea71dd76eee247611d
        # add address should be same as main function length
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_func_length)
        
        sys.stdout = temp

        # TODO error occurs because of return 0; -> no information about return 0 address
        print(">>> Emulation done. Below is the CPU context")

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()