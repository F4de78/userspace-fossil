from compress_pickle import load as load_c 
from compress_pickle import dump as dump_c
from pprint import pprint

def main():
    # Load the compressed file

    data_dir = "../msc-thesis/us-dump/test/extracted"

    data = load_c(f'{data_dir}/results.lzma')
    data_dll = load_c(f'{data_dir}/extracted_dll.lzma')
    pprint(data)


    if data['arrays_strings'] != []:
        c = 0
        print("arrays_strings:")
        for trees in data['arrays_strings']:
            print(f"arrays_strings #{c}")
            pprint(trees.__dict__)
            pprint([hex(p) for p in trees.__dict__['ptrs_list']])
            c += 1

    if data['cicles'] != []:
        c = 0
        print("cicles:")
        for trees in data['cicles']:
            print(f"cicles #{c}")
            pprint(trees.__dict__)
            pprint([hex(p) for p in trees.__dict__['ptrs_list']])
            c += 1

    if data['trees'] != []:
        c = 0
        print("Trees:")
        for trees in data['trees']:
            print(f"Tree #{c}")
            pprint(trees.__dict__)
            pprint([hex(p) for p in trees.__dict__['ptrs_list']])
            c += 1

    if data['linears'] != []:
        c = 0
        print("Doubly linked lists:")
        for trees in data['linears']:
            print(f"dll #{c}")
            pprint(trees.__dict__)
            pprint([hex(p) for p in trees.__dict__['ptrs_list']])
            c += 1

    if data['lists'] != []:
        c = 0
        print("Trees:")
        for list in data['lists']:
            print(f"LList #{c}")
            pprint(list.__dict__)
            
            pprint([hex(p) for p in list.__dict__['ptrs_list']])
            c += 1




if __name__ == '__main__':
    main()