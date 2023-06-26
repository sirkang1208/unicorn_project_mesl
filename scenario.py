from __future__ import print_function
from unicorn import *
from capstone import *
from xprint import to_hex, to_x_32
from unicorn.arm_const import *
from uprint import *
from elfloader import *
import random

REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}

def select_scenario(uc,address,cmd,dat = 0):
    if cmd == 'p':
        pass
    elif cmd == 's':
        skip_insn(uc)
    elif cmd == 'r':
        change_reg(uc,dat)
    elif cmd == 'm':
        change_mem(uc,address,dat)
    elif cmd == 'setr':
        set_reg(uc,0xFFFFFFFF)
    elif cmd == 'setm':
        set_mem(uc,address,dat)
    elif cmd == 'clrr':
        set_reg(uc,0x0)
    elif cmd == 'clrm':
        clr_mem(uc,address,dat)
    elif cmd == 'bfr':
        bit_flip_reg(uc)
    elif cmd == 'bfm':
        bit_flip_mem(uc,address,dat)
    elif cmd == 'randr':
        rand_reg(uc)
    elif cmd == 'randm':
        rand_mem(uc,address,dat)
    else:
        pass

def skip_insn(uc):
    pc_data = uc.reg_read(UC_ARM_REG_PC)
    uc.reg_write(REG["pc"],pc_data+4)

# change random register 
def change_reg(uc,data):
    r_num = random.randint(0,16)
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
    uc.reg_write(REG[r_num],int(data))

def change_mem(uc,addr,data):
    res_data = data.to_bytes(4,'little')
    print(res_data)
    uc.mem_write(addr,res_data)
    print_mem(uc,addr-4,12)

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
        cvt_x = 0xFF - cvt_x
        res_x = cvt_x.to_bytes(1,"little")
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
def set_mem(uc, address,s_size):
    for i in range(s_size):
        uc.mem_write(address+i, b'\x11')

    print_mem(uc,address,s_size)

# set all data 0 - mem
def clr_mem(uc, address,c_size):
    for i in range(c_size):
        uc.mem_write(address+i, b'\x00')

    print_mem(uc,address,c_size)

# set all data bit_flip - mem
def bit_flip_mem(uc, address,b_size):
    for i in range(b_size):
        x = uc.mem_read(address + i)
        res_x = flip(x)
        uc.mem_write(address+i, res_x)

    print_mem(uc,address,b_size)

# set data random - mem
def rand_mem(uc, address,r_size):
    for i in range(r_size):
        x = random.randint(0,0xFF)
        res_x = x.to_bytes(1,'little')
        uc.mem_write(address+i,res_x)

    print_mem(uc,address,r_size)
