from __future__ import print_function
from unicorn import *
from capstone import *
from unicorn.arm_const import *
from scenario import *
from uprint import *
from setdata_thumb import *
#import clock
import sys

REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}

def make_refer(input, addr):
    global InIdx, count, refsIdx, reffIdx

    f = open('reference_thumb.txt', 'a')
    # Initialize Capstone in ARM mode
    mc = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    # prev setting of disassemble
    mc.syntax = None
    mc.detail = True

    # copy mnemonics to copy_mne
    # add modified register at copy_mne
    for insn in mc.disasm(input, addr):

        if (e_sec[refsIdx][1]) == insn.address:
            f.write("\nsection\t\t : %s\n\n" % (e_sec[refsIdx][3]))
            print(e_sec[refsIdx])
            print(refsIdx)
            refsIdx += 1
            if refsIdx == len(e_sec):
                refsIdx = len(e_sec)-1
        if (func_list[reffIdx][1]-1) == insn.address:
            f.write("\nfunction\t : %s\n\n" % (func_list[reffIdx][0]))
            print(func_list[reffIdx])
            print(reffIdx)
            reffIdx += 1
            if reffIdx == len(func_list):
                reffIdx = len(func_list)-1

        f.write("0x%x:\t%s\t%s\n" %(insn.address, insn.mnemonic, insn.op_str)) #remove comment when make reference file
        line = []
        copy_mne.append(line)
        copy_mne[InIdx].append(insn.mnemonic)
        (regiread,regi_write) = insn.regs_access()
        for r in regi_write:
            copy_mne[InIdx].append(insn.reg_name(r))
        InIdx += 1

    f.close()

    if len(copy_mne)/int(len(ARM_CODE)/2) < 1:
        count += 1
        line = []
        copy_mne.append(line)
        copy_mne[InIdx].append("NONE")
        InIdx += 1
        retaddr = ADDRESS+InIdx*2
        with open(elf_file_name, "rb") as f:
            f.seek(retaddr,0)
            fcode = f.read()

        return fcode, retaddr
    else:
        return 0, addr

def auto_set(uc, size, stack_addr, stack_len):
    uc.mem_map(0x0,1024)
    uc.mem_map(ADDRESS & 0xFFFFFFFE,size)
    uc.mem_map(stack_addr-stack_len,stack_len)
    uc.reg_write(UC_ARM_REG_SP, stack_addr)
    uc.reg_write(UC_ARM_REG_FP, stack_addr)
    uc.reg_write(UC_ARM_REG_LR, exit_addr) 

def upload(uc):
    for i in range(len(e_sec)):
        # read file from start address to eof
        with open(elf_file_name, "rb") as f:
            f.seek(e_sec[i][1],0)
            cod = f.read(e_sec[i][2])

        if e_sec[i][0] != 0:
            uc.mem_write(e_sec[i][0],cod)
        else:
            uc.mem_write(e_sec[i][1],cod) 

def get_scene():
    se_input = []
    
    se_data = script_data["scenario"]
    for i in range(len(se_data)):
        se_data[i]["address"] = int(se_data[i]["address"], 16)
        se_input.append(list(se_data[i].values())) # ex: [[34110, 's', 1234], [34216, 'setr', 1234]]

    return se_input

# write log data to file
def write_log(uc, address, user_data):

    temp = sys.stdout
    addr = int((address-ADDRESS)/2)
    print("[" + str(hex(address)) + "]", end=' ')
    print("instruction :", user_data[addr][0],end=' ')
    print("/ register data :", end="")
    print_all_reg(uc)
    print("/ modified register : ", end ='')
    print(user_data[addr][1:], end = ' ')
    print_mem(uc,address,2)
    sys.stdout = temp

def code_hook(uc, address, size, user_data):
    global print_len_i
    temp = sys.stdout
    sys.stdout = open(filename,'a')
    print = script_data["printLog"]
    
    try:
        if print[print_len_i]["point_s"] <= hex(address) and print[print_len_i]["point_f"] >= hex(address):
            write_log(uc, address, user_data)

        if hex(address) == print[print_len_i]["point_f"] and print_len_i != len(print) - 1:
            print_len_i += 1
    
    except:
        write_log(uc, address, user_data)
    sys.stdout = temp

    if address == exit_addr_real - 1:
        uc.emu_stop()


#scenario hook
def scene_hook(uc,address,size, user_data):
    for i in range(len(user_data)):
        if len(user_data[i]) == 2:
            if user_data[i][0] == address:
                print("address : ", end = "")
                print(address)
                select_scenario(uc,address, user_data[i][1])
        else:
            if user_data[i][0] == address:
                print("address : ", end = "")
                print(address)
                select_scenario(uc,address, user_data[i][1],user_data[i][2])

#get output data if you want
def get_output_data(uc,out_addr,len_addr):
    output = []
    len_mem = uc.mem_read(len_addr,4)
    cvt_len = int.from_bytes(len_mem, byteorder='little')
    # change mem to int
    for i in range(cvt_len):
        out_mem = uc.mem_read(out_addr+i*4,4)
        cvt_output = int.from_bytes(out_mem,byteorder="little")
        output.append(cvt_output)
    return output
