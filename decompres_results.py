import argparse
from compress_pickle import load as load_c 
from pprint import pprint
import matplotlib.pyplot as plt
import numpy as np
import os

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
        for offset in dll.__dict__['embedded_strs'].keys():
            print(f"{MAGENTA}Embedded strings (address) @ {RESET}{YELLOW}{offset}{RESET}:{[hex(s) for s in dll.__dict__['embedded_strs'][offset]]} ")

        for offset in dll.__dict__['embedded_strs'].keys():
            print(f"{MAGENTA}Embedded strings @ {RESET}{YELLOW}{offset}{RESET}:{[strings.get(s) for s in dll.__dict__['embedded_strs'][offset]]} ")

        for offset in dll.__dict__['pointed_strs'].keys():
            print(f"{MAGENTA}Pointed strings (address) @ {RESET}{YELLOW}{offset}{RESET}: {[hex(s) for s in dll.__dict__['pointed_strs'][offset]]} ")
 
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
        #pprint(cicles.__dict__)
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

def print_structure_lengths(data):
    """Print lengths of all retrieved data structures."""
    
    print(f"{GREEN}Structure Lengths:{RESET}")
    
    # Arrays
    if data.get('arrays'):
        print(f"\n{MAGENTA}Arrays:{RESET}")
        for i, array in enumerate(data['arrays']):
            print(f"Array #{i}: {len(array.__dict__['ptrs_list'])} elements")
            
    # String Arrays  
    if data.get('arrays_strings'):
        print(f"\n{MAGENTA}String Arrays:{RESET}")
        for i, array in enumerate(data['arrays_strings']):
            print(f"Array #{i}: {len(array.__dict__['strs_array'])} strings")
            
    # Trees
    if data.get('trees'):
        print(f"\n{MAGENTA}Trees:{RESET}")
        for i, tree in enumerate(data['trees']):
            print(f"Tree #{i}: {len(tree.__dict__['nodes'])} nodes")
            
    # Linked Lists
    if data.get('lists'):
        print(f"\n{MAGENTA}Linked Lists:{RESET}") 
        for i, ll in enumerate(data['lists']):
            print(f"List #{i}: {len(ll.__dict__['ptrs_list'])} nodes")
            
    # Doubly Linked Lists
    if data.get('linears'):
        print(f"\n{MAGENTA}Doubly Linked Lists:{RESET}")
        for i, dll in enumerate(data['linears']):
            print(f"List #{i}: {len(dll.__dict__['ptrs_list'])} nodes")
            
    # Circular Lists
    if data.get('cicles'):
        print(f"\n{MAGENTA}Circular Lists:{RESET}")
        for i, cl in enumerate(data['cicles']):
            print(f"List #{i}: {len(cl.__dict__['ptrs_list'])} nodes")

    # Derived Structures
    if data.get('derived'):
        derived = data['derived']
        print(f"\n{MAGENTA}Derived Structures:{RESET}")
        
        if derived['arrays'][0]:
            print("\nDerived Arrays:")
            for i, arr in enumerate(derived['arrays'][0]):
                print(f"Array #{i}: {len(arr.__dict__['ptrs_list'])} elements")
                
        if derived['trees'][0]:
            print("\nDerived Trees:")
            for i, tree in enumerate(derived['trees'][0]):
                print(f"Tree #{i}: {len(tree.__dict__.get('nodes', [])) or len(tree.__dict__['ptrs_list'])} nodes")
                
        if derived['linears'][0]:
            print("\nDerived Linear Lists:")
            for i, dll in enumerate(derived['linears'][0]):
                print(f"List #{i}: {len(dll.__dict__['ptrs_list'])} nodes")
                
        if derived['lists'][0]:
            print("\nDerived Lists:")
            for i, ll in enumerate(derived['lists'][0]):
                print(f"List #{i}: {len(ll.__dict__['ptrs_list'])} nodes")

def count_structures(data, latex=False, plot=True):
    """Count data structures and return results dictionary."""
    
    counts = {
        'Basic Structures': {
            'Arrays': len(data['arrays']),
            'Arrays of strings': len(data['arrays_strings']),
            'Trees': len(data['trees']),
            'Linked lists': len(data['lists']),
            'Doubly linked lists': len(data['linears']), 
            'Circular lists': len(data['cicles'])
        },
        'Derived Structures': {
            'Derived arrays': len(data['derived']['arrays'][0]),
            'Derived trees': len(data['derived']['trees'][0]),
            'Derived linears': len(data['derived']['linears'][0]),
            'Derived lists': len(data['derived']['lists'][0])
        }
    }

    # Print counts
    print(f"{GREEN}Count of data structures:{RESET}")
    for name, count in counts['Basic Structures'].items():
        print(f"{MAGENTA}{name}: {RESET}{count}")
        
    print(f"{GREEN}Count of referenced data structures:{RESET}")
    for name, count in counts['Derived Structures'].items():
        print(f"{MAGENTA}{name}: {RESET}{count}")

    if latex:
        latex_table = r"""
    \begin{table}
        \centering
        \begin{tabular}{lr}
        \toprule
        \textbf{Data Structure} & \textbf{Count} \\
        \midrule"""
        
        for category in counts.values():
            for name, count in category.items():
                latex_table += f"\n        {name} & {count} \\\\"
                
        latex_table += r"""
        \bottomrule
        \end{tabular}
        \caption{Count of different data structures}
        \label{table:data_structures_count}
    \end{table}
    """
        return latex_table

    return counts

def plot_structures(data):
    """Create bar plot showing counts of different data structures."""
    
    # Prepare data
    structures = {
        'Arrays': len(data['arrays']),
        'String Arrays': len(data['arrays_strings']), 
        'Trees': len(data['trees']),
        'Linked Lists': len(data['lists']),
        'Doubly Linked': len(data['linears']),
        'Circular Lists': len(data['cicles']),
        'Derived Arrays': len(data['derived']['arrays'][0]),
        'Derived Trees': len(data['derived']['trees'][0]),
        'Derived Linear': len(data['derived']['linears'][0]),
        'Derived Lists': len(data['derived']['lists'][0])
    }

    # Create plot
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Plot bars
    x = np.arange(len(structures))
    bars = ax.bar(x, list(structures.values()))
    
    # Customize plot
    ax.set_xticks(x)
    ax.set_xticklabels(structures.keys(), rotation=45, ha='right')
    ax.set_ylabel('Count')
    ax.set_title('Data Structures Found')

    # Adjust layout to prevent label cutoff
    plt.tight_layout()
    
    return fig



def multiple_run_details(dir_name, archive_name):
    directory = os.fsencode(dir_name)
    n_structures = []

    for name in os.listdir(directory):
        if not name.startswith(bytes("extracted_", 'utf-8')):
            continue
        
        data_path = f'{dir_name}/{name.decode("utf-8")}'
        data = load_c(f"{data_path}/{archive_name}")
        strings = load_c(f"{data_path}/extracted_strs.lzma")
        print(f"{RED}Data from {data_path}{RESET}")
        n_structures.append(count_structures(data))

    # Flatten the nested dictionaries
    structure_types = set()
    for run_dict in n_structures:
        for category in run_dict.values():
            structure_types.update(category.keys())
    
    # Setup plot
    fig, ax = plt.subplots(figsize=(15, 10))
    x = np.arange(len(n_structures))
    width = 0.1
    
    # Plot bars for each structure type
    for i, struct_type in enumerate(sorted(structure_types)):
        # Get values across all runs for this structure type
        values = []
        for run in n_structures:
            # Search in both Basic and Derived structures
            for category in run.values():
                if struct_type in category:
                    values.append(category[struct_type])
                    break
            else:
                values.append(0)
                
        offset = width * i - width * len(structure_types)/2 + width/2
        ax.bar(x + offset, values, width, label=struct_type)
        
        # Add value labels on bars
        # for j, v in enumerate(values):
        #     if v > 0:
        #         ax.text(j + offset, v, str(v), ha='center', va='bottom')

    # Customize plot
    ax.grid(axis='y', linestyle='-', alpha=0.5)
    ax.set_ylabel('Count')
    ax.set_xlabel('# Extraction')
    ax.set_title('Data Structures Found in fortune per Extraction')
    ax.set_xticks(x)
    ax.set_xticklabels([f'Extraction {i+1}' for i in range(len(n_structures))], rotation=45, ha='right')
    ax.legend(loc='upper left')

    plt.tight_layout()
    plt.savefig(f"{dir_name}/structures_by_run.pdf")

def plot_dll_lengths(dir_name, archive_name):
    """Plot lengths of doubly linked lists across multiple runs using line plot."""
    directory = os.fsencode(dir_name)
    dll_lengths = []

    # Collect DLL lengths from each run
    for name in os.listdir(directory):
        if not name.startswith(bytes("extracted_", 'utf-8')):
            continue
            
        data_path = f'{dir_name}/{name.decode("utf-8")}'
        data = load_c(f"{data_path}/{archive_name}")
        
        run_lengths = []
        # change this to plot another ds length
        if data.get('linears'):
            for dll in data['linears']:
                run_lengths.append(len(dll.__dict__['ptrs_list']))
        dll_lengths.append(run_lengths)

    # Setup plot
    fig, ax = plt.subplots(figsize=(12, 6))
    x = range(len(dll_lengths))
    
    # Plot lines for each DLL
    max_dlls = max(len(l) for l in dll_lengths)
    colors = plt.cm.tab20(np.linspace(0, 1, max_dlls))
    markers = ['o', 's', '^', 'D', 'v', '<', '>', 'p', '*']  # Different markers for each line
    
    for dll_idx in range(max_dlls):
        values = []
        for run_lengths in dll_lengths:
            values.append(run_lengths[dll_idx] if dll_idx < len(run_lengths) else None)
                
        ax.plot(x, values, 
               marker=markers[dll_idx % len(markers)],
               markersize=8,
               linewidth=2,
               label=f'DLL #{dll_idx+1}', 
               color=colors[dll_idx])

    # Customize plot
    ax.grid(True, linestyle='--', alpha=0.3)
    ax.set_ylabel('Length')
    ax.set_xlabel('Extraction #')
    ax.set_title('Doubly Linked List Lengths per Extraction')
    ax.set_xticks(x)
    ax.set_xticklabels([f'#{i+1}' for i in range(len(dll_lengths))])
    
    ax.legend(bbox_to_anchor=(1.01, 1),
             loc='upper left',
             ncol=1)

    plt.tight_layout()
    plt.savefig(f"{dir_name}/dll_lengths.pdf", bbox_inches='tight')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('data_dir', type=str, help='Directory of result', default="../msc-thesis/us-dump/test/extracted")
    parser.add_argument('result_lzma', type=str, help='Name of compressed results', default="result.lzma")
    parser.add_argument('--debug', help='Enable debug', default=False,action='store_true')
    parser.add_argument('--count','-c', help='Print the count of the data structure found', default=False,action='store_true')
    parser.add_argument('--plot','-p', type=str, help='Plot graph')
    parser.add_argument('--multiple_core','-m', help='Extract details from multiple core',action='store_true')

    parser.add_argument('--arrays','-a', help='Print arrays if any', default=False, action='store_true')
    parser.add_argument('--derived','-d', help='Print derived structures if any', default=False, action='store_true')
    parser.add_argument('--arrays_strings','-as', help='Print arrays of strings if any', default=False, action='store_true')
    parser.add_argument('--trees','-t', help='Print trees if any', default=False, action='store_true')
    parser.add_argument('--linked_list','-ll', help='Print linked lists if any', default=False, action='store_true')
    parser.add_argument('--doubly_linked_list','-dll', help='Print doubly linked list if any', default=False, action='store_true')
    parser.add_argument('--circular_list','-cl', help='Print circular list if any', default=False, action='store_true')

    args = parser.parse_args()
    # Load the compressed file
    if args.multiple_core:
        multiple_run_details(args.data_dir, args.result_lzma)
        #plot_dll_lengths(args.data_dir, args.result_lzma)
        return

    data = load_c(f'{args.data_dir}/{args.result_lzma}')
    strings = load_c(f'{args.data_dir}/extracted_strs.lzma')

    if args.debug:
        pprint(data)
        print("")
        pprint(strings)

    print_header()

    if args.plot:
        fig1 = plot_structures(data)
        fig1.savefig(f'{args.plot}/data_structures_count.png')
        # fig2.savefig(f'{args.plot}/data_structures_lengths.png')   


    print(f"{GREEN}Pointer size: {RESET}{data['pointer_size']}")
    print("")

    if args.count:
        latex = count_structures(data)
        print(latex)

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