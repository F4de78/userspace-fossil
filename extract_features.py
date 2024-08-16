#!/usr/bin/env python3

import argparse
import json
import random
from compress_pickle import dump, load
from addrspaces import ELFDump, get_virtspace
import functools
import logging
from threading import Timer
import os
import signal
import subprocess
import ctypes
from pathlib import Path


def stop_radare(a,b):
    raise Exception

def subprocess_check_output_strip(cmd: str):
    return subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT).strip().decode(errors='ignore')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dump_elf', help='Memory dump in ELF format', type=str)
    parser.add_argument('dest_prefix', help='Prefix for the output files')
    # parser.add_argument('--convert', default=False, action='store_true', help="Convert a physical memory layout ELF in a virtual one")
    parser.add_argument('--ignore_page', help="Physical page to be ignored during the virtual-to-physical mapping (can be repeated)", action='append', type=functools.partial(int, base=0))
    parser.add_argument('--debug', help="Enable debug printer", default=False, action="store_true")
    parser.add_argument('--ip', help="Look for network packets/structs containing this IP address (format xxx.xxx.xxx.xxx)", action="append", type=str, default=[])
    # parser.add_argument('--mac', help="Look for network packets/structs containing this MAC address (format AA:BB:CC:DD:EE:FF)", action="append", type=str, default=[])
    args = parser.parse_args()

    if not args.ignore_page:
        args.ignore_page = []

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    dest_path = Path(args.dest_prefix)
    if not dest_path.exists():
        print("Destination path does not exist")
        return(1)

    # Load the ELF file and parse it
    print("Load ELF...")
    import time as t
    #t.sleep(15)
    phy_elf = ELFDump(args.dump_elf)
    
    print("Get virtspace...")
    virtspace = get_virtspace(phy_elf, args.ignore_page)

    # Retrieve pointers, reverse-pointers, strings and memory bitmap and save them
    # if args.ip or args.mac:
    #     virtspace.retrieve_network_packets(args.ip, None) # TODO: macs
    virtspace.retrieve_pointers()
    virtspace.retrieve_strings()
    virtspace.create_bitmap()

    # Produce a kernel VAS only ELF file
    print("Export kernel VAS ELF...")
    virtspace.export_virtual_memory_elf(str(dest_path) + "/extracted_kernel.elf", True, False)
    ghidra_path = os.getenv("GHIDRA_PATH")
    if not ghidra_path:
        print("Error: GHIDRA_PATH not set!")
        return(1)
    # Collect addresses from static analysis
    print("Start static analysis...")
    out_filename = f"{str(dest_path)}.json"
    arch = phy_elf.get_machine_data()["Architecture"]
    processor = f"X86:LE:{virtspace.wordsize * 8}:default -cspec gcc" if arch == "X86" else f"AARCH64:LE:{virtspace.wordsize * 8}:v8A -cspec default" # Support only X86 and AARCH64 
    ghidra_cmd = os.path.join(ghidra_path, 'support/analyzeHeadless') \
                 + f" /tmp/ ghidra_project_{random.randint(0, 1000000)}" \
                 + f" -import {str(dest_path)}/extracted_kernel.elf" \
                 + f" -processor {processor}" \
                 + f" -scriptPath {os.path.join(os.path.dirname(__file__),'ghidra')}" \
                 + f" -postScript export_xrefs.py {out_filename}"
    try:
        ret = subprocess_check_output_strip(ghidra_cmd)
        with open(out_filename, "r") as output:
            (xrefs_data, functions) = json.load(output)

        # Filter for valid xrefs_only
        print("Static analysis ended, filtering results...")
        if virtspace.wordsize == 8:
            convf = lambda x: ctypes.c_uint64(x).value
        else:
            convf = lambda x: ctypes.c_uint32(x).value
        xrefs_data = [convf(x) for x in xrefs_data.values() if virtspace.v2o[convf(x)] != -1]
        xrefs_data = set(xrefs_data)
        functions = [convf(x) for x in functions.values() if virtspace.v2o[convf(x)] != -1]
        functions = set(functions)

    except subprocess.CalledProcessError as e:
        print("[!] Error in static analysis!")
        print(e)
        xrefs_data = {}
    
    # Save data structures
    print("Saving features...")
    dump(virtspace.v2o, str(dest_path) + "/extracted_v2o.lzma")
    dump(virtspace.o2v, str(dest_path) + "/extracted_o2v.lzma")
    dump(virtspace.ptrs, str(dest_path) + "/extracted_ptrs.lzma")
    dump(virtspace.rptrs, str(dest_path) + "/extracted_rptrs.lzma")
    dump(virtspace.strs, str(dest_path) + "/extracted_strs.lzma")
    dump(virtspace.mem_btm, str(dest_path) + "/extracted_btm.lzma")
    # dump(virtspace.packets if args.ip or args.mac else [], str(dest_path) + "_pkts.lzma")
    dump(xrefs_data, str(dest_path) + "/extracted_xrefs.lzma")
    dump(functions, str(dest_path) + "/extracted_functions.lzma")

if __name__ == '__main__':
    main()
