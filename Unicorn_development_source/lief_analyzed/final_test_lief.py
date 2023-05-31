import lief
import sys
import unicorn as uc
import capstone as cs
import operator

elf_file = lief.parse("/home/kibong/Desktop/unicorn_project_mesl/Unicorn_development_source/compiled_program/global_val")
functions = {}

try:
    for f in elf_file.exported_functions:
        tmpn = f.name
        c = 0
        while tmpn in functions:
            c += 1
            tmpn = f.name + str(c)
        functions[tmpn] = f.address
except:
    pass

d1 = sorted(functions.items(), key = lambda x : x[1] )
func_sort = dict(d1)

#start address : _init()
print(list(func_sort.values())[0])

#entry_point
print(elf_file.entrypoint)

#main_address
addr = func_sort.get('main')
print(addr)

for index, (key,elem) in enumerate(func_sort.items()):
    if key == 'main':
        a = index
        print(a)
        break

func_list = list(func_sort.items())
main_length = func_list[a+1][1] - addr
print(hex(main_length))

