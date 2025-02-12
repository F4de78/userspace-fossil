import argparse
from compress_pickle import load as load_c 
from pprint import pprint

GREEN = "\033[92m"
RED = "\033[91m"
MAGENTA = "\033[95m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def print_header():
    dinosaur = """
                       __
                      / _)
             _.----._/ /
            /         /
         __/ (  | (  |
        /__.-'|_|--|_|
 ______                _  _ 
|  ____|              (_)| |
| |__  ___   ___  ___  _ | |
|  __|/ _ \ / __|/ __|| || |
| |  | (_) |\__   __ \| || |
|_|   \___/ |___/|___/|_||_|
u s e r s p a c e 
      
      """
    print(f"{RED}{dinosaur}{RESET}")

def print_derived(data,strings):
    print(f"{GREEN}Derived structures:{RESET}")
    if data['derived']['arrays'][0] != []:
        for c, derived in enumerate(data['derived']['arrays'][0]):
            print(f"{RED}Derived arrays #{c}{RESET}")
            print(f"{MAGENTA}Embedded strings: {RESET}{derived.__dict__['embedded_strs']}")
            print(f"{MAGENTA}Pointed strings: {RESET}{derived.__dict__['pointed_strs']}")
            print(f"{MAGENTA}Shape: {RESET}{derived.__dict__['shape']}")
            print(f"{MAGENTA}Parent: {RESET}{derived.__dict__['parent']}")
            print("")
    if data['derived']['trees'][0] != []:
        for c, derived in enumerate(data['derived']['trees'][0]):
            print(f"{RED}Derived trees #{c}{RESET}")
            print(f"{MAGENTA}Embedded strings: {RESET}{derived.__dict__['embedded_strs']}")
            print(f"{MAGENTA}Pointed strings: {RESET}{derived.__dict__['pointed_strs']}")
            print(f"{MAGENTA}Shape: {RESET}{derived.__dict__['shape']}")
            print(f"{MAGENTA}Parent: {RESET}{derived.__dict__['parent']}")
            print("")
    if data['derived']['linears'][0] != []:
        for c, derived in enumerate(data['derived']['linears'][0]):
            print(f"{RED}Doubly Linked List #{c}{RESET}")
            print(f"{MAGENTA}Embedded strings (address): {RESET}{derived.__dict__['embedded_strs']}")

            for offset in derived.__dict__['embedded_strs'].keys():
                print(f"{MAGENTA}Embedded strings @ {RESET}{YELLOW}{offset}{RESET}:{[strings.get(s) for s in derived.__dict__['embedded_strs'][offset]]} ")

            print(f"{MAGENTA}Pointed strings: {RESET}{derived.__dict__['pointed_strs']}")

            for offset in derived.__dict__['pointed_strs'].keys():
                print(f"{MAGENTA}Pointed strings @ {RESET}{YELLOW}{offset}{RESET}: {[strings.get(s) for s in derived.__dict__['pointed_strs'][offset]]} ")

            print(f"{MAGENTA}# Pointer: {RESET}{len(derived.__dict__['ptrs_list'])}")
            print(f"{MAGENTA}Pointer list: {RESET}{[hex(addr) for addr in derived.__dict__['ptrs_list']]}")
            print(f"{MAGENTA}Shape: {RESET}{derived.__dict__['shape']}")
            print(f"{MAGENTA}Referenced?: {RESET}{derived.__dict__['referenced']}")
            #pprint(dll.__dict__)
            print("")
    if data['derived']['lists'][0] != []:
        for c, derived in enumerate(data['derived']['lists'][0]):
            print(f"{RED}Linked List #{c}{RESET}")
            print(f"{MAGENTA}Embedded strings: {RESET}{derived.__dict__['embedded_strs']}")

            for offset in derived.__dict__['embedded_strs'].keys():
                print(f"{MAGENTA}Embedded strings @ {RESET}{YELLOW}{offset}{RESET}:{[strings.get(s) for s in derived.__dict__['embedded_strs'][offset]]} ")

            print(f"{MAGENTA}Pointed strings: {RESET}{derived.__dict__['pointed_strs']}")

            for offset in derived.__dict__['pointed_strs'].keys():
                print(f"{MAGENTA}Pointed strings @ {RESET}{YELLOW}{offset}{RESET}: {[strings.get(s) for s in derived.__dict__['pointed_strs'][offset]]} ")
            
            print(f"{MAGENTA}# Pointer: {RESET}{len(derived.__dict__['ptrs_list'])}")
            print(f"{MAGENTA}Pointer list: {RESET}{[hex(addr) for addr in derived.__dict__['ptrs_list']]}")
            print(f"{MAGENTA}Shape: {RESET}{derived.__dict__['shape']}")
            print(f"{MAGENTA}Referenced?: {RESET}{derived.__dict__['referenced']}")
            #pprint(ll.__dict__)
            print("")
def print_arrays(data):
    print(f"{GREEN}Arrays:{RESET}")
    for c, array in enumerate(data['arrays']):
        print(f"{RED}Array #{c}{RESET}")
        print(f"{MAGENTA}Pointer list: {RESET}{array.__dict__['ptrs_list']}")
        print(f"{MAGENTA}Strings: {RESET}{array.__dict__['strs_array']}")
        print(f"{MAGENTA}Referenced?: {RESET}{array.__dict__['referenced']}")
        print("")

def print_arrays_str(data,strings):
    print(f"{GREEN}Arrays of Strings:{RESET}")
    for c, array in enumerate(data['arrays_strings']):
        print(f"{RED}Array #{c}{RESET}")
        print(f"{MAGENTA}# Pointers: {RESET}{len(array.__dict__['ptrs_list'])}")
        print(f"{MAGENTA}Pointer list: {RESET}{[hex(addr) for addr in array.__dict__['ptrs_list']]}")
        print(f"{MAGENTA}# strings: {RESET}{len(array.__dict__['strs_array'])}")
        print(f"{MAGENTA}Strings address: {RESET}{[hex(addr) for addr in array.__dict__['strs_array']]}")
        print(f"{MAGENTA}Embedded strings: {RESET} {[strings.get(s) for s in array.__dict__['strs_array']]} ")
        print(f"{MAGENTA}Referenced?: {RESET}{array.__dict__['referenced']}")
        print("")

def print_trees(data,strings):   
    print(f"{GREEN}Tree:{RESET}")
    for c, tree in enumerate(data['trees']):
        #pprint(tree.__dict__)
        print(f"{RED}Trees #{c}{RESET}")
        print(f"{MAGENTA}# Nodes: {RESET}{len(tree.__dict__['nodes'])}")
        print(f"{MAGENTA}Nodes address: {RESET}{[hex(addr) if (addr) else addr for addr in tree.__dict__['nodes']]}") # check if the address is not None and convert to hex

        for offset in tree.__dict__['embedded_strs'].keys():
            print(f"{MAGENTA}Embedded strings @ {RESET}{YELLOW}{offset}{RESET}:{[strings.get(s) for s in tree.__dict__['embedded_strs'][offset]]} ")

        print(f"{MAGENTA}Pointed strings: {RESET}{tree.__dict__['pointed_strs']}")

        print(f"{MAGENTA}shape: {RESET}{tree.__dict__['shape']}")
        print(f"{MAGENTA}Referenced?: {RESET}{tree.__dict__['referenced']}")
        print("")

def print_ll(data,strings):   
    print(f"{GREEN}Linked lists:{RESET}")
    for c, ll in enumerate(data['lists']):
        print(f"{RED}Linked List #{c}{RESET}")
        print(f"{MAGENTA}Embedded strings: {RESET}{ll.__dict__['embedded_strs']}")

        for offset in ll.__dict__['embedded_strs'].keys():
            print(f"{MAGENTA}Embedded strings @ {RESET}{YELLOW}{offset}{RESET}:{[strings.get(s) for s in ll.__dict__['embedded_strs'][offset]]} ")

        print(f"{MAGENTA}Pointed strings: {RESET}{ll.__dict__['pointed_strs']}")

        for offset in ll.__dict__['pointed_strs'].keys():
            print(f"{MAGENTA}Pointed strings @ {RESET}{YELLOW}{offset}{RESET}: {[strings.get(s) for s in ll.__dict__['pointed_strs'][offset]]} ")
        
        print(f"{MAGENTA}# Pointer: {RESET}{len(ll.__dict__['ptrs_list'])}")
        print(f"{MAGENTA}Pointer list: {RESET}{[hex(addr) for addr in ll.__dict__['ptrs_list']]}")
        print(f"{MAGENTA}Shape: {RESET}{ll.__dict__['shape']}")
        print(f"{MAGENTA}Referenced?: {RESET}{ll.__dict__['referenced']}")
        #pprint(ll.__dict__)
        print("")

def print_dll(data,strings):   
    print(f"{GREEN}Doubly linked list:{RESET}")
    for c, dll in enumerate(data['linears']):
        print(f"{RED}Doubly Linked List #{c}{RESET}")
        print(f"{MAGENTA}Embedded strings (address): {RESET}{dll.__dict__['embedded_strs']}")

        for offset in dll.__dict__['embedded_strs'].keys():
            print(f"{MAGENTA}Embedded strings @ {RESET}{YELLOW}{offset}{RESET}:{[strings.get(s) for s in dll.__dict__['embedded_strs'][offset]]} ")

        print(f"{MAGENTA}Pointed strings: {RESET}{dll.__dict__['pointed_strs']}")

        for offset in dll.__dict__['pointed_strs'].keys():
            print(f"{MAGENTA}Pointed strings @ {RESET}{YELLOW}{offset}{RESET}: {[strings.get(s) for s in dll.__dict__['pointed_strs'][offset]]} ")

        print(f"{MAGENTA}# Pointer: {RESET}{len(dll.__dict__['ptrs_list'])}")
        print(f"{MAGENTA}Pointer list (next): {RESET}{[hex(addr) for addr in dll.__dict__['ptrs_list']]}")
        print(f"{MAGENTA}Pointer list (prev): {RESET}{[hex(addr) for addr in dll.__dict__['ptrs_list_back']]}")
        print(f"{MAGENTA}Shape: {RESET}{dll.__dict__['shape']}")
        print(f"{MAGENTA}Referenced?: {RESET}{dll.__dict__['referenced']}")
        #pprint(dll.__dict__)
        print("")

def print_cicles(data,strings):   
    print(f"{GREEN}Circula list:{RESET}")
    for c, cicles in enumerate(data['cicles']):
        print(f"{RED}Circular List #{c}{RESET}")
        print(f"{MAGENTA}Embedded strings: {RESET}{cicles.__dict__['embedded_strs']}")

        for offset in cicles.__dict__['embedded_strs'].keys():
            print(f"{MAGENTA}Embedded strings @ {RESET}{YELLOW}{offset}{RESET}:{[strings.get(s) for s in cicles.__dict__['embedded_strs'][offset]]} ")

        print(f"{MAGENTA}Pointed strings: {RESET}{cicles.__dict__['pointed_strs']}")

        for offset in cicles.__dict__['pointed_strs'].keys():
            print(f"{MAGENTA}Pointed strings @ {RESET}{YELLOW}{offset}{RESET}: {[strings.get(s) for s in cicles.__dict__['pointed_strs'][offset]]} ")

        print(f"{MAGENTA}# Pointer: {RESET}{len(cicles.__dict__['ptrs_list'])}")
        print(f"{MAGENTA}Pointer list: {RESET}{[hex(addr) for addr in cicles.__dict__['ptrs_list']]}")
        print(f"{MAGENTA}Shape: {RESET}{cicles.__dict__['shape']}")
        print(f"{MAGENTA}Referenced?: {RESET}{cicles.__dict__['referenced']}")
        print("")

def count_structures(data):
    print(f"{GREEN}Count of data structures:{RESET}")
    print(f"{MAGENTA}Arrays: {RESET}{len(data['arrays'])}")
    print(f"{MAGENTA}Arrays of strings: {RESET}{len(data['arrays_strings'])}")
    print(f"{MAGENTA}Trees: {RESET}{len(data['trees'])}")
    print(f"{MAGENTA}Linked lists: {RESET}{len(data['lists'])}")
    print(f"{MAGENTA}Doubly linked lists: {RESET}{len(data['linears'])}")
    print(f"{MAGENTA}Circular lists: {RESET}{len(data['cicles'])}")
    print(f"{GREEN}Count of referenced data structures:{RESET}")
    print(f"{MAGENTA}Derived arrays: {RESET}{len(data['derived']['arrays'][0])}")
    print(f"{MAGENTA}Derived trees: {RESET}{len(data['derived']['trees'][0])}")
    print(f"{MAGENTA}Derived linears: {RESET}{len(data['derived']['linears'][0])}")
    print(f"{MAGENTA}Derived lists: {RESET}{len(data['derived']['lists'][0])}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('data_dir', type=str, help='Directory of result', default="../msc-thesis/us-dump/test/extracted")
    parser.add_argument('result_lzma', type=str, help='Name of compressed results', default="result.lzma")
    parser.add_argument('--debug', help='Enable debug', default=False,action='store_true')
    parser.add_argument('--count','-c', help='Print the count of the data structure found', default=False,action='store_true')

    parser.add_argument('--arrays','-a', help='Print arrays if any', default=False, action='store_true')
    parser.add_argument('--derived','-d', help='Print derived structures if any', default=False, action='store_true')
    parser.add_argument('--arrays_strings','-as', help='Print arrays of strings if any', default=False, action='store_true')
    parser.add_argument('--trees','-t', help='Print trees if any', default=False, action='store_true')
    parser.add_argument('--linked_list','-ll', help='Print linked lists if any', default=False, action='store_true')
    parser.add_argument('--doubly_linked_list','-dll', help='Print doubly linked list if any', default=False, action='store_true')
    parser.add_argument('--circular_list','-cl', help='Print circular list if any', default=False, action='store_true')

    args = parser.parse_args()
    # Load the compressed file
    data = load_c(f'{args.data_dir}/{args.result_lzma}')
    strings = load_c(f'{args.data_dir}/extracted_strs.lzma')

    if args.debug:
        pprint(data)
        print("")
        pprint(strings)

    print_header()

    print(f"{GREEN}Pointer size: {RESET}{data['pointer_size']}")
    print("")

    if args.count:
        count_structures(data)

    if data.get('arrays') and args.arrays:
        print_arrays(data)

    if data.get('derived') and args.derived:
        print_derived(data,strings)

    if data.get('arrays_strings') and args.arrays_strings:
        print_arrays_str(data,strings)

    if data.get('trees') and args.trees:
        print_trees(data,strings)

    if data.get('lists') and args.linked_list:
        print_ll(data,strings)

    if data.get('linears') and args.doubly_linked_list:
        print_dll(data,strings)

    if data.get('lists') and args.circular_list:
        print_cicles(data,strings)





if __name__ == '__main__':
    main()