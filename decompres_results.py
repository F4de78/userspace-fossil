from compress_pickle import load as load_c 
from compress_pickle import dump as dump_c
from pprint import pprint

def main():
    # Load the compressed file

    data_dir = "../msc-thesis/us-dump/test/extracted"

    data = load_c(f'{data_dir}/results.lzma')

    # c = 0
    # for trees in data['trees']:
    #     print(f"Tree #{c}")
    #     pprint(trees.__dict__)
    #     pprint([hex(p) for p in trees.__dict__['ptrs_list']])
    #     c += 1

    # searched_tree = data['trees'][0].__dict__['embedded_strs'][-32]
    # pprint([hex(s) for s in searched_tree])

    pprint(data['trees'][0].__dict__)




if __name__ == '__main__':
    main()