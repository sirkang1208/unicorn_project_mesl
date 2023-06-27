from __future__ import print_function
from functions import *

def main():

    print("Emulating the code...")

    try:
        # Initialize Unicorn in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # map 4MB memory for this emulation
        mu.mem_map(ADDRESS, 4*1024*1024)
        mu.mem_map(0x0,1024)
        # map stack region as much as stack size
        mu.mem_map(STACK_ADDRESS - STACK_SIZE, STACK_SIZE)

        upload(mu,elf_file_name,e_sec)
        
        # initialize machine registers
        # stack pointer must be initialized
        mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_FP, STACK_ADDRESS)
        mu.reg_write(UC_ARM_REG_LR, exit_addr) 

        # make copy_mne list until eof
        # used only once when creating a reference file
        reccod = ARM_CODE
        recaddr = ADDRESS
        while len(copy_mne)/int(len(ARM_CODE)/4) < 0.99:
            reccod, recaddr = make_insn_array(reccod,recaddr)

        scene_input = get_scene()
                
        # address command data
        if len(scene_input) == 0:
            pass
        else:
            mu.hook_add(UC_HOOK_CODE, scene_hook, scene_input, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))
        
        # function_skip
        # mu.hook_add(UC_HOOK_CODE, test_hook, copy_mne, begin= func_test, end=func_test + 52)

        mu.hook_add(UC_HOOK_CODE, code_hook, copy_mne, begin= ADDRESS, end= ADDRESS + len(ARM_CODE))
        
        # add address should be same as main function length
        mu.emu_start(emu_ADDRESS, emu_ADDRESS + main_func_length)

        print(">>> Emulation done. Below is the CPU context")

        OutData = get_output_data(mu,OutData_addr,length_addr)
        print("OutData = ", end="")
        print(OutData)

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()