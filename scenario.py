from __future__ import print_function
from unicorn import *
from capstone import *
from xprint import to_hex, to_x_32
from unicorn.arm_const import *
from main import *
from elfloader import *
import random

REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}

# change random register 
def change_reg(uc):
    r_num = random.randint(0,17)
    r_num = str(r_num)
    if r_num == '11':
        r_num = 'fp'
    elif r_num == '12':
        r_num = 'ip'
    elif r_num == '13':
        r_num = 'sp'
    elif r_num == '14':
        r_num = 'lr'
    elif r_num == '15':
        r_num = 'pc'
    elif r_num == '16':
        r_num = 'cpsr'
    REG.get(r_num,"알 수 없는")
    if REG == "알 수 없는":
        print("wrong register number")
        change_reg(uc)
    print("selected register is : ", end='')
    print(r_num)
    data = input('change data to : ')
    print(data)
    uc.reg_write(REG[r_num],int(data))

def select_mode():
    mode = input("input mode - r(register) or m(memory) : ")
    if mode != 'r' and mode != 'm':
        print("wrong input, please try again")
        select_mode
    return mode

def select_scenario(uc,address,cmd):
    if cmd == 'p':
        pass
    elif cmd == 's':
        return
    elif cmd == 'r':
        change_reg(uc)
    elif cmd == 'set':
        mode = select_mode()
        if mode == 'r':
            set_reg(uc,0x1)
        else:
            s_range = input("input modify range : ")
            set_mem(uc,address,s_range)
    elif cmd == 'clr':
        mode = select_mode()
        if mode == 'r':
            set_reg(uc,0x0)
        else:
            c_range = input("input modify range : ")
            clr_mem(uc,address,c_range)
    elif cmd == 'bf':
        mode = select_mode()
        if mode == 'r':
            bit_flip_reg(uc)
        else:
            b_range = input("input modify range : ")
            bit_flip_mem(uc,address,b_range)
    elif cmd == 'rand':
        mode = select_mode()
        if mode == 'r':
            rand_reg(uc)
        else:
            r_range = input("input modify range : ")
            rand_mem(uc,address,r_range)
    else:
        print("wrong input, please enter again")
        select_scenario(uc,cmd,address)


# set all reg by data
def set_reg(uc,data):
    uc.reg_write(REG['0'],data)
    uc.reg_write(REG['1'],data)
    uc.reg_write(REG['2'],data)
    uc.reg_write(REG['3'],data)
    uc.reg_write(REG['4'],data)
    uc.reg_write(REG['5'],data)
    uc.reg_write(REG['6'],data)
    uc.reg_write(REG['7'],data)
    uc.reg_write(REG['8'],data)
    uc.reg_write(REG['9'],data)
    uc.reg_write(REG['10'],data)
    uc.reg_write(REG['fp'],data)
    uc.reg_write(REG['ip'],data)
    uc.reg_write(REG['sp'],data)
    uc.reg_write(REG['lr'],data)
    uc.reg_write(REG['pc'],data)
    uc.reg_write(REG['cpsr'],data)
    print_all_reg(uc)

def flip(x):
    if type(x) == bytes:
        cvt_x = int.from_bytes(x, byteorder='little')
        cvt_x = 0xFFFFFFFF - cvt_x
        res_x = cvt_x.to_bytes(4,"little")
        return res_x
    else:
        cvrt_x = 0xFFFFFFFF - x
        return cvrt_x
    
# set all reg bit_flip
def bit_flip_reg(uc):
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

    uc.reg_write(REG['0'],flip(r0))
    uc.reg_write(REG['1'],flip(r1))
    uc.reg_write(REG['2'],flip(r2))
    uc.reg_write(REG['3'],flip(r3))
    uc.reg_write(REG['4'],flip(r4))
    uc.reg_write(REG['5'],flip(r5))
    uc.reg_write(REG['6'],flip(r6))
    uc.reg_write(REG['7'],flip(r7))
    uc.reg_write(REG['8'],flip(r8))
    uc.reg_write(REG['9'],flip(r9))
    uc.reg_write(REG['10'],flip(r10))
    uc.reg_write(REG['fp'],flip(fp))
    uc.reg_write(REG['ip'],flip(ip))
    uc.reg_write(REG['sp'],flip(sp))
    uc.reg_write(REG['lr'],flip(lr))
    uc.reg_write(REG['pc'],flip(pc))
    uc.reg_write(REG['cpsr'],flip(cpsr)) 
    print_all_reg(uc)

# set reg random
def rand_reg(uc):
    uc.reg_write(REG['0'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['1'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['2'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['3'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['4'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['5'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['6'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['7'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['8'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['9'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['10'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['fp'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['ip'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['sp'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['lr'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['pc'],random.randint(0,0xFFFFFFFF))
    uc.reg_write(REG['cpsr'],random.randint(0,0xFFFFFFFF))
    print_all_reg(uc)

# set all data 1 - mem
def set_mem(uc, address,s_range):
    for i in range(s_range/4):
        uc.mem_write(address+i*4, b'\x01\x00\x00\x00')

# set all data 0 - mem
def clr_mem(uc, address,c_range):
    for i in range(c_range/4):
        uc.mem_write(address+i*4, b'\x00\x00\x00\x00')

# set all data bit_flip - mem
def bit_flip_mem(uc, address,b_range):
    for i in range(b_range/4):
        x = uc.mem_read(address + i*4)
        res_x = flip(x)
        uc.mem_write(address+i*4, res_x)

# set data random - mem
def rand_mem(uc, address,r_range):
    for i in range(r_range/4):
        x = random.randint(0,0xFFFFFFFF)
        res_x = x.to_bytes(4,'little')
        uc.mem_write(address+i*4,res_x)

def print_selection():
    print(" 'p' for pass ")
    print(" 's' for skip ")
    print(" 'r' for register modify ")
    print(" 'set' for set mem 1 ")
    print(" 'clr' for set mem 0 ")
    print(" 'bf' for flip the bit ")
    print(" 'rand' for set mem random data ")
