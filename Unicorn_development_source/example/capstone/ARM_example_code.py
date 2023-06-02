from unicorn import *
from unicorn.arm_const import *

ARM_CODE32 = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3

# memory address where emulation starts
# address must finished in 0
ADDRESS = 0x10000


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
    
    print(">>> R0 = 0x%x" %r0)
    print(">>> R1 = 0x%x" %r1)
    print(">>> R2 = 0x%x" %r2)
    print(">>> R3 = 0x%x" %r3)
    print(">>> R4 = 0x%x" %r4)
    print(">>> R5 = 0x%x" %r5)
    print(">>> R6 = 0x%x" %r6)
    print(">>> R7 = 0x%x" %r7)
    print(">>> R8 = 0x%x" %r8)
    print(">>> R9 = 0x%x" %r9)
    print(">>> R10 = 0x%x" %r10)
    print(">>> FP = 0x%x" %fp)
    print(">>> IP = 0x%x" %ip)
    print(">>> SP = 0x%x" %sp)
    print(">>> LR = 0x%x" %lr)
    print(">>> PC = 0x%x" %pc)
    print(">>> CPSR = 0x%x" %cpsr)
    
def print_mem(uc):
    tot_mem = uc.mem_read(ADDRESS,len(ARM_CODE32))
    print(">>> MEM = ", end = "")
    for i in range(len(tot_mem)):
        print("\\x%x" %tot_mem[i], end = "")
    print()

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

def change_mem(uc,a):
    addr = input("input address : ")

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

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    #break every each instruction and get input
    while(1):
        print('-----------------------------')
        print("function: ")
        print('r: change register')
        print('m: change memory')
        print('rv: print all register')
        print('mv: print memory')
        print('p: pass') #프로그램 출력 p
        print('q: quit') #프로그램 종료 q
        print('-----------------------------')
        a = input('input your function : ')

        select_func(uc,a)

        if a == 'q':
            break

    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


    # do single step debugging here


def main():

    print("Emulate ARM code")

    try:
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        # Initialize emulator in ARM mode


        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS,2*1024*1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM_CODE32)

        # initialize machine registers
        mu.reg_write(UC_ARM_REG_R0, 0x1234)
        mu.reg_write(UC_ARM_REG_R2, 0x6789)
        mu.reg_write(UC_ARM_REG_R3, 0x3333)
        mu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF) #All application flags turned on
        
        # tracing one instruction at ADDRESS with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS+len(ARM_CODE32))
        
        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE32))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        #print(debug())
        
        print_all_reg(mu)
        print_mem(mu)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == "__main__":
    main()