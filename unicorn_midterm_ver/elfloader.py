import lief

class ElfLoader:
    def __init__(self, elf_file):
        self.elf_file = lief.parse(elf_file)
        self.elf_file_name = elf_file
        self.functions = {}
        self.func_sort = {}
        self.func_list = []
        self.setup()

    def setup(self):
        try:
            for f in self.elf_file.exported_functions:
                tmp = f.name
                c = 0
                while tmp in self.functions:
                    c += 1
                    tmp = f.name + str(c)
                self.functions[tmp] = f.address
        except:
            pass
        self.func_sort = dict(sorted(self.functions.items(), key = lambda x : x[1]))
        self.func_list = list(self.func_sort.items())

    def get_func_address(self, func_name):
        try:
            return self.func_sort.get(func_name)
        except:
            print("Err: it is not a function name that exists in that file.")
            exit()
    
    def get_main_len(self):
        for index, (key,elem) in enumerate(self.func_sort.items()):
            if key == 'main':
                a = index
                
        return self.func_list[a+1][1] - self.func_sort.get('main')
    
    def get_start_address(self):
        return list(self.func_sort.values())[0]

    def get_code(self,ADDRESS):
        with open(self.elf_file_name, "rb") as f:
            f.seek(ADDRESS,0)
            code = f.read()
        return code
            
    def section_list_make(self):
        e_sections = []
        count = 0
        for section in self.elf_file.sections:
            line = []
            e_sections.append(line)
            e_sections[count].append(section.virtual_address)
            e_sections[count].append(section.offset)
            e_sections[count].append(section.original_size)
            count += 1
        return e_sections

    def print_section_data(self):
        for section in self.elf_file.sections:
            print('section name : ',end = "")
            print(section.name)
            print('section Flash_address : ',end = "")
            print(section.offset)
            print('section RAM_address : ',end = "")
            print(section.virtual_address)
            print('section content length : ',end = "")
            print(len(section.content))