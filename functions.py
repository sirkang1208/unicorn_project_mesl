from __future__ import print_function
from unicorn import *
from capstone import *
from unicorn.arm_const import *
from scenario import *
from uprint import *
from setdata import *
#import clock
import sys

REG = {'0' : UC_ARM_REG_R0, '1' : UC_ARM_REG_R1, '2' : UC_ARM_REG_R2, '3' : UC_ARM_REG_R3,
            '4' : UC_ARM_REG_R4, '5' : UC_ARM_REG_R5, '6' : UC_ARM_REG_R6, '7' : UC_ARM_REG_R7,
            '8' : UC_ARM_REG_R8, '9' : UC_ARM_REG_R9, '10' : UC_ARM_REG_R10, "fp" : UC_ARM_REG_FP,
            "ip" : UC_ARM_REG_IP, "sp" : UC_ARM_REG_SP, "lr" : UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
            "cpsr" : UC_ARM_REG_CPSR}

def upload(uc,elf_file_name,e_sec):
    for i in range(len(e_sec)):
        # read file from start address to eof
        with open(elf_file_name, "rb") as f:
            f.seek(e_sec[i][1],0)
            cod = f.read(e_sec[i][2])

        if e_sec[i][0] != 0:
            uc.mem_write(e_sec[i][0],cod)
        else:
            uc.mem_write(e_sec[i][1],cod) 

# make_insn_array(ARM_CODE,ADDRESS)
def make_insn_array(input,addr):
    global InIdx
    global count
    #sys.stdout = open("./reference.txt",'a') #remove comment when make reference file
    #temp = sys.stdout
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
        #print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str)) #remove comment when make reference file
        #sys.stdout = temp
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

def get_scene():
    se_input = []
    
    se_data = script_data["Scenario"]
    for i in range(len(se_data)):
        se_data[i]["address"] = int(se_data[i]["address"], 16)
        se_input.append(list(se_data[i].values())) # ex: [[34110, 's', 1234], [34216, 'setr', 1234]]

    return se_input

# write log data to file
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
    # print("/ clock count: ", clock.cycle_cal(user_data[addr][0]))
    sys.stdout = temp

# hook every instruction and fetch information we need
def code_hook(uc, address, size, user_data):
    #input result in .txt file
    global line_count,skip_len_i
    temp = sys.stdout
    sys.stdout = open(filename,'a')
    skip = script_data["SkipLog"]
    line_count += 1
    
    try:
        if skip[skip_len_i]["point_s"] <= line_count and skip[skip_len_i]["point_f"] >= line_count:
            write_log(uc, address, user_data, line_count)

        if line_count == skip[skip_len_i]["point_f"] and skip_len_i != len(skip) - 1:
            skip_len_i += 1
    
    except:
        write_log(uc, address, user_data, line_count) # default: log every instructions

    sys.stdout = temp

    if address == exit_addr_real:
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
        print(out_mem)
        cvt_output = int.from_bytes(out_mem,byteorder="little")
        output.append(cvt_output)
    return output
