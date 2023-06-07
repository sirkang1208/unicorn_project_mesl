import lief

class ElfLoader:
    def __init__(self, elf_file):
        self.elf_file = lief.parse(elf_file)
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
    
    def get_start_add(self):
        return list(self.func_sort.values())[0]

