import lief
import sys
import unicorn as uc
import capstone as cs

# def elfloader(elf_file, emu, map_virtual_segments=False, verbose=False):
# emu = rainbow_arm
# rainbow_arm -> emu = uc, disasm = cs, pc = UC_ARM_REG_PC

elf_file = lief.parse("/home/kibong/Desktop/unicorn_project_mesl/Unicorn_development_source/compiled_program/global_val")
map_virtual_segments=False
verbose = False
unc = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM+uc.UC_MODE_LITTLE_ENDIAN)
cap = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM+cs.CS_MODE_LITTLE_ENDIAN)
emu = {}
emu.functions = {}
if verbose:
    print(f"[x] Loading ELF segments...")

if len(list(elf_file.segments)) > 0:
    for segment in elf_file.segments:
        # Only consider LOAD segments
        if segment.type != lief.ELF.SEGMENT_TYPES.LOAD:
            continue

        if map_virtual_segments:
            print(segment.virtual_address)
            print(segment.virtual_address + segment.virtual_size)
            print(segment.content)
            print(verbose)
            unc.mem_write(segment.virtual_address, bytes(segment.content))
        else:
            print(segment.physical_address)
            print(segment.physical_address + segment.physical_size)
            print(verbose)
            print(segment.content)
            unc.mem_write(segment.physical_address, bytes(segment.content))
else:
    # if there are no segments, still attempt to map .text area
    section = elf_file.get_section(".text")
    print(section)
    print(section.virtual_address)
    print(section.virtual_address + section.virtual_size)
    print(section.content)
    print(verbose)
    unc.mem_write(section.virtual_address, bytes(section.content))

# Handle relocations
for r in elf_file.relocations:
    if r.symbol.is_function:
        if r.symbol.value == 0:
            rsv = r.address
            print(rsv)
        else:
            rsv = r.symbol.value
            print(rsv)
        # emu = rainbow_arm -> information of functions
        emu.functions[r.symbol.name] = rsv
        if verbose:
            print(f"Relocating {r.symbol.name} at {r.address:x} to {rsv:x}")
        # emu = rainbow_arm -> input value in address -> what value?
        emu[r.address] = rsv

# lief > 0.10 -> our version is 0.13.0
try:
    for f in elf_file.exported_functions:
        tmpn = f.name
        print(tmpn)
        c = 0
        while tmpn in emu.functions:
            c += 1
            tmpn = f.name + str(c)
        emu.functions[tmpn] = f.address
except:
    pass

## TODO: when the ELF has relocated functions exported, LIEF fails on get_function_address
for i in elf_file.symbols:
    if i.type == lief.ELF.SYMBOL_TYPES.FUNC:
        try:
            tmpn = i.name
            addr = i.value
            if tmpn in emu.functions.keys():
                if emu.functions[tmpn] != addr:
                    c = 0
                    while tmpn in emu.functions.keys():
                        c += 1
                        tmpn = i.name + str(c)
                    emu.functions[tmpn] = addr
            else:
                emu.functions[tmpn] = addr
        except Exception as exc:
            if verbose:
                print(exc)

emu.function_names = {emu.functions[x]: x for x in emu.functions.keys()}
print(elf_file.entrypoint)



sys.stdout = open('global_val.txt','w')
print(elf_file)