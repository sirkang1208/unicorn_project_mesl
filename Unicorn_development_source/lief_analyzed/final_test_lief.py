import lief
import sys
import unicorn as uc
import capstone as cs
import operator

elf_file = lief.parse("/home/kibong/Desktop/unicorn_project_mesl/Unicorn_development_source/compiled_program/toy_ex_mod_1")
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
print(func_sort)

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

symb_out = elf_file.get_symbol("OutData")
symb_len = elf_file.get_symbol("length")
print(symb_out)
print(symb_out.name)
print(symb_out.size)
print(symb_out.value)
print(symb_len)
print(symb_len.name)
print(symb_len.size)
print(symb_len.value)

# bss.content = bytes([0x33] * bss.size)

sys.stdout = open('toy_ex_mod_add.txt','w')
print(elf_file)