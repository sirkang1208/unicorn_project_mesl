from __future__ import print_function
from functions_arm import *

# board dependent data, must be set before the emulation
STACK_ADDRESS = 0x20000000
STACK_SIZE = 0x10000

def main():
    refcod = ARM_CODE
    refaddr = ADDRESS
    while len(copy_mne)/int(len(ARM_CODE)/4) < 1:
        refcod, refaddr = make_refer(refcod,refaddr)

    print(refaddr)
    print("Emulating the code...")

    try:
        # Initialize Unicorn in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # set memory and data for this emulation
        auto_set(mu,4*1024*1024,STACK_ADDRESS,STACK_SIZE)

        upload(mu)

        # make copy_mne list until eof
        # used only once when creating a reference file

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
        mu.emu_start(emu_ADDRESS, finish_ADDRESS)

        print(">>> Emulation done. Below is the CPU context")

        OutData = get_output_data(mu,OutData_addr,length_addr)
        print("OutData = ", end="")
        print(OutData)

    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()