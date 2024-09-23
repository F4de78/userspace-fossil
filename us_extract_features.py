#!/usr/bin/env python3

from typing import DefaultDict
from collections import defaultdict, Counter
from tqdm import tqdm
import argparse
import json
import random
from compress_pickle import dump, load
from addrspaces import ELFDump, get_virtspace
import functools
import logging
import extract_pointers
from threading import Timer
import os
import signal
import subprocess
import ctypes
import time as t
import numpy as np
from pathlib import Path
from string import ascii_uppercase, ascii_lowercase, digits
from bitarray import bitarray



def subprocess_check_output_strip(cmd: str):
    return subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT).strip().decode(errors='ignore')

def retrieve_strings(elf, rptrs, min_len=3, max_symbols_threshold=0.3):
    # Get strings with physical addresses [(string, paddr), ...]
    print("Retrieving strings...")
    strings = {}
    strings_offsets = retrieve_strings_offsets(elf, min_len)
    # rw_strings = []

    for string in strings_offsets:
        value, offset = string

        # Ignore strings which are not part of the memory dump (eg, ELF dump constants etc.)
        vaddrs = elf.o2v[offset]
        if not vaddrs:
            continue
        
        for vaddr in vaddrs:
            # HEURISTICS if there are more than max_symbol_threshold
            # symbols ignore it
            if sum(not c.isalnum() for c in value)/len(value) >= max_symbols_threshold:
                continue
            strings[vaddr] = value

            # in_rw = bool(self.pmasks[vaddr][0] & 0x2)
            # if in_rw:
            #     rw_strings.append(vaddr)

            # Add substrings referenced by pointers
            for i in range(1, len(value)):
                substr_vaddr = i + vaddr
                if substr_vaddr in rptrs:
                    # HEURISTICS if there are more than max_symbol_threshold
                    # symbols percentage ignore it
                    if sum(not c.isalnum() for c in value[i:])/len(value[i:]) >= max_symbols_threshold:
                        continue
                    strings[substr_vaddr] = value[i:]
                    # if in_rw:
                    #     rw_strings.append(substr_vaddr)
    return strings
    # self.rw_strings = set(rw_strings)

def retrieve_strings_offsets(elf, min_len=3):
    # Generate random separator
    separator = ''.join(random.choice(ascii_lowercase + ascii_uppercase + digits) for _ in range(10))

    # Use the external program `strings` which is order of magnitude more
    # fast (collect also UTF-16)!
    elf_path = os.path.realpath(elf.elf_filename)
    strings_proc = subprocess.Popen(["strings", "-a", "-n", f"{min_len}", "-t", "x", "-w", "-s", separator, f"{elf_path}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    strings_out, strings_stderr = strings_proc.communicate()
    if strings_proc.returncode:
        print(strings_stderr)
        raise OSError

    strings_proc = subprocess.Popen(["strings", "-a", "-e", "l" if elf.machine_data["Endianness"] == "little" else "b", "-n", f"{min_len}", "-t", "x", "-w", "-s", separator, f"{elf_path}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    strings_out_utf16, strings_stderr = strings_proc.communicate()
    if strings_proc.returncode:
        print(strings_stderr)
        raise OSError

    strings_out = strings_out + " " + strings_out_utf16

    # Translate file offset in physical addresses (ignoring ELF internal strings)
    strings_offsets = []
    for string in strings_out.split(separator):

        try:
            p_offset, value = string.lstrip().split(maxsplit=1)
            p_offset = int(p_offset, 16)
        except: # Ignore not valid lines
            continue

        # Allow only NULL-terminated strings
        try:
            if elf.elf_buf[p_offset + len(value)] != 0:
                continue
        except: # End of File
            pass

        if elf.o2v[p_offset] == -1:
            continue

        strings_offsets.append((value, p_offset))

    return strings_offsets

def create_bitmap(elf):
    """Create a bitmap starting from the ELF file containing 0 if the byte
    is 0, 1 otherwise"""
    print("Creating bitmap...")
    mem_btm = bitarray()
    mem_btm.pack(elf.elf_buf.tobytes())
    return mem_btm

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
    # import time as t
    # t.sleep(15)
    print("Reading virtspace from ELF dump...")
    elf = ELFDump(args.dump_elf)

    logging.debug("virtual addr:")
    for addr in elf.v2o.get_values():
        logging.debug((hex(addr[0]),(hex(addr[1][0]),hex(addr[1][1]))))

    logging.debug("virtual addr offsets:")
    for offset in elf.o2v.get_values():
        logging.debug((hex(offset[0]), [hex(h) for h in offset[1]]))

    # wordsize value changes depending on the architecture 
    wordsize = 8 if "64" in elf.get_machine_data()["Architecture"] else 4 
    word_type = None
    word_fmt = None
    if wordsize == 4:
        word_type = np.uint32
        if elf.machine_data["Endianness"] == "big":
            word_fmt = np.dtype(">u4")
        else:
            word_fmt = np.dtype("<u4")
    else:
        word_type = np.uint64
        if elf.machine_data["Endianness"] == "big":
            word_fmt = np.dtype(">u8")
        else:
            word_fmt = np.dtype("<u8")
    
    print("wordsize:",wordsize, "word_type:",word_type, "word_fmt:",word_fmt)

    #dmap, rptr = retrieve_pointers(elf,wordsize,word_fmt)
    dmap = {}
    extract_pointers.main()
    logging.debug("dmap:")
    for k, v in dmap.items():
        logging.debug(f"{hex(k)} -> {hex(v)}")
    strings = retrieve_strings(elf,rptr)
    bm = create_bitmap(elf)

    # Produce a kernel VAS only ELF file
    print(f" {str(dest_path)} Export VAS ELF...")
    # export_virtual_memory_elf(elf, str(dest_path) + "/extracted_kernel.elf", False, False)
    ghidra_path = os.getenv("GHIDRA_PATH")
    if not ghidra_path:
        print("Error: GHIDRA_PATH not set!")
        return(1)
    # Collect addresses from static analysis
    print("Start static analysis...")
    out_filename = f"{str(dest_path)}.json"
    arch = elf.get_machine_data()["Architecture"]
    print (f"Architecture: {arch}")
    processor = f"x86:LE:{wordsize * 8}:default -cspec gcc" if "X86" in arch or "386" in arch else f"AARCH64:LE:{wordsize * 8}:v8A -cspec default" # Support only X86 and AARCH64 
    print(f"Ghidra Processor: {processor}")
    ghidra_cmd = os.path.join(ghidra_path, 'support/analyzeHeadless') \
                 + f" /tmp/ ghidra_project_{random.randint(0, 1000000)}" \
                 + f" -import {str(dest_path)}/dump.elf" \
                 + f" -processor {processor}" \
                 + f" -scriptPath {os.path.join(os.path.dirname(__file__),'ghidra')}" \
                 + f" -postScript export_xrefs.py {out_filename}"
    print(ghidra_cmd)
    functions = []
    try:
        ret = subprocess_check_output_strip(ghidra_cmd)
        with open(out_filename, "r") as output:
            (xrefs_data, functions) = json.load(output)

        # Filter for valid xrefs_only
        print("Static analysis ended, filtering results...")
        if wordsize == 8:
            convf = lambda x: ctypes.c_uint64(x).value
        else:
            convf = lambda x: ctypes.c_uint32(x).value
        xrefs_data = [convf(x) for x in xrefs_data.values() if elf.v2o[convf(x)] != -1]
        xrefs_data = set(xrefs_data)
        functions = [convf(x) for x in functions.values() if elf.v2o[convf(x)] != -1]
        functions = set(functions)

    except subprocess.CalledProcessError as e:
        print("[!] Error in static analysis!")
        print(e)
        xrefs_data = {}
    
    # Save data structures
    print("Saving features...")
    dump(elf.v2o, str(dest_path) + "/extracted_v2o.lzma")
    dump(elf.o2v, str(dest_path) + "/extracted_o2v.lzma")
    dump(dmap, str(dest_path) + "/extracted_ptrs.lzma") # self.ptrs = dmap
    dump(rptr, str(dest_path) + "/extracted_rptrs.lzma") # self.rptrs = rmap
    dump(strings, str(dest_path) + "/extracted_strs.lzma")
    dump(bm, str(dest_path) + "/extracted_btm.lzma")
    dump(xrefs_data, str(dest_path) + "/extracted_xrefs.lzma")
    dump(functions, str(dest_path) + "/extracted_functions.lzma")

if __name__ == '__main__':
    main()
