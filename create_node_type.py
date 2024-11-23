from compress_pickle import load as load_c 
from compress_pickle import dump as dump_c
from pprint import pprint

# from ghidra.program.model.data import DataTypeConflictHandler
# from ghidra.program.model.data import EndianSettingsDefinition
# from ghidra.app.util.cparser.C import CParser

# Load the compressed file

data_dir = "../msc-thesis/us-dump/test/extracted"
file_path = f'{data_dir}/results.lzma'
print(file_path)
data = load_c(file_path)
pprint(data['trees'][0].__dict__)

ptr_size = 8
dests_offsets = (0, 8)
estimated_size = 32

struct_fields = ""
for field in range(estimated_size // ptr_size):
    if field * ptr_size in dests_offsets:
        struct_fields += f"\tNode* _ptr_at_{field * ptr_size};\n"
    else:
        struct_fields += f"\tchar[8] maybe_data;\n"

struct_node_txt = f"""struct Node {{\n  {struct_fields}}};"""
print(struct_node_txt)
