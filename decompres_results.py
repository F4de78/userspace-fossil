from compress_pickle import load as load_c 
from compress_pickle import dump as dump_c
from pprint import pprint

def main():
    # Load the compressed file

    data_dir = "../msc-thesis/us-dump/test/extracted"

    data = load_c(f'{data_dir}/results.lzma')
    # pprint([ hex(ptr) for  ptr in data['arrays_strings'][2].__dict__['ptrs_list']])
    pointed_strings = data['linears'][0].__dict__['pointed_strs'][-40]
    pprint([hex(ptr) for ptr in pointed_strings])
    # c = 0
    # for trees in data['trees']:
    #     print(f"Tree #{c}")
    #     pprint(trees.__dict__)
    #     pprint([hex(p) for p in trees.__dict__['ptrs_list']])
    #     c += 1




if __name__ == '__main__':
    main()