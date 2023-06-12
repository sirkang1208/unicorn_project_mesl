import lief
import sys
import unicorn as uc
import capstone as cs
import operator

elf_file = lief.parse("/home/kibong/Desktop/unicorn_project_mesl/Unicorn_development_source/compiled_program/toy_ex_simplify_add")

for section in elf_file.sections:
    print("section name                 : ",end="")
    print(section.name)
    print("section size                 : ",end="")
    print(section.size)
    print("section content length       : ",end="")
    print(len(section.content))
    print("section original_size        : ",end="")
    print(section.original_size)
    print("section file_offset          : ",end="")
    print(section.file_offset)
    print("section offset               : ",end="")
    print(section.offset)
    print("section virtual_address      : ",end="")
    print(section.virtual_address)
    print()


data = elf_file.get_section(".data")
