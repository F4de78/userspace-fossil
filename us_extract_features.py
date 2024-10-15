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
import extract_pointers as ep
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

def retrieve_strings(elf, endianness, rptrs, min_len=3, max_symbols_threshold=0.3):
    # Get strings with physical addresses [(string, paddr), ...]
    strings = {}
    strings_offsets = retrieve_strings_offsets(elf, endianness,  min_len)
    # print(f"str offsets: {[hex(x[1]) for x in strings_offsets]}")
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
            print(f"file offset: {hex(offset)} \t vaddrs: {hex(vaddr)} \t value: {strings[vaddr]} ")

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
                    # print(f"file offset: {hex(offset)} value: {strings[substr_vaddr]} vaddrs: {hex(substr_vaddr)}")
                    # if in_rw:
                    #     rw_strings.append(substr_vaddr)
    return strings
    # self.rw_strings = set(rw_strings)

def retrieve_strings_offsets(elf, endianness, min_len=3):
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

    # extracts utf-16 strings
    strings_proc = subprocess.Popen(["strings", "-a", "-e", "l" if endianness == "little" else "b"  , "-n", f"{min_len}", "-t", "x", "-w", "-s", separator, f"{elf_path}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    strings_out_utf16, strings_stderr = strings_proc.communicate()
    if strings_proc.returncode:
        print(strings_stderr)
        raise OSError

    strings_out = strings_out + " " + strings_out_utf16

    # Translate file offset in virtual addresses (ignoring ELF internal strings)
    strings_offsets = []
    for string in strings_out.split(separator):

        try:
            p_offset, value = string.lstrip().split(maxsplit=1)
            p_offset = int(p_offset, 16)
            # print(f"p_offset: {hex(p_offset)}, value: {value}")
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
    parser.add_argument('cpu_info', help='json file with information about the CPU', type=str)
    parser.add_argument('dest_prefix', help='Prefix for the output files')
    parser.add_argument('--debug', help="Enable debug printer", default=False, action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    dest_path = Path(args.dest_prefix)
    if not dest_path.exists():
        print("Destination path does not exist")
        return(1)
    
    cpu_info = Path(args.cpu_info)
    if not cpu_info.exists():
        print("Destination path does not exist")
        return(1)
    with open(args.cpu_info) as f:
        cpu_infos = json.load(f)

    print("[*] Reading ELF dump")
    # Load the ELF file and parse it
    elf = ELFDump(args.dump_elf)

    # wordsize value changes depending on the architecture 
    wordsize = 8 if "64" in cpu_infos['architecture'] else 4 
    word_fmt = '<I' if wordsize == 4 else '<Q'

    # Extract pointers from the memory data
    print("[*] Extracting pointers")
    ptrs = {}
    for region, i in zip(elf.segments_intervals, range(len(elf.segments_intervals))):
        logging.debug(f"[ptr] Searching pointers in memory region {i}...")
        valid_pointers = []
        # get every memory region data
        mem_region_data = elf.elf_buf[region[2]:region[2]+region[3]]
        valid_pointers.extend(ep.extract_pointers(elf.segments_intervals, mem_region_data, wordsize, word_fmt, (region[0], region[1]), region[0]))
        valid_pointers.sort()
        for pointer_address, target_address in valid_pointers:
            logging.debug(f"\t ptr at 0x{pointer_address:08X} -> 0x{target_address:08X}")
            ptrs[pointer_address] = target_address
        logging.debug(f"[ptr] Found {len(valid_pointers)} pointers in memory region {i}.")
    # create reverse pointers dictionary
    rptr = {v: k for k, v in ptrs.items()}
    print(f"[!] Found {len(ptrs)} pointers")

    print("[*] Retrieving strings")
    strings = retrieve_strings(elf,cpu_infos['endianness'],rptr)
    print(f"[!] Found {len(strings)} strings")
    print("[*] Creating bitmap")
    bm = create_bitmap(elf)

    ghidra_path = os.getenv("GHIDRA_PATH")
    if not ghidra_path:
        print("Error: GHIDRA_PATH not set!")
        return(1)
    # Collect addresses from static analysis
    print("[*] Start Ghidra static analysis...")
    out_filename = f"{str(dest_path)}.json"
    arch = cpu_infos['architecture']
    processor = f"x86:LE:{wordsize * 8}:default -cspec gcc" if "x86" in arch or "386" in arch else f"AARCH64:LE:{wordsize * 8}:v8A -cspec default" # Support only X86 and AARCH64 
    logging.debug(f"Ghidra Processor: {processor}")
    ghidra_cmd = os.path.join(ghidra_path, 'support/analyzeHeadless') \
                 + f" /tmp/ ghidra_project_{random.randint(0, 1000000)}" \
                 + f" -import {str(dest_path)}/core.elf" \
                 + f" -processor {processor}" \
                 + f" -scriptPath {os.path.join(os.path.dirname(__file__),'ghidra')}" \
                 + f" -postScript export_xrefs.py {out_filename}"
    functions = []
    logging.debug(f"Running Ghidra command: {ghidra_cmd}")
    try:
        ret = subprocess_check_output_strip(ghidra_cmd)
        logging.debug(f"Ghidra output:\n{ret}")
        with open(out_filename, "r") as output:
            (xrefs_data, functions) = json.load(output)
        # Filter for valid xrefs_only
        print("[*] Static analysis ended, filtering results...")
        if wordsize == 8:
            convf = lambda x: ctypes.c_uint64(x).value
        else:
            convf = lambda x: ctypes.c_uint32(x).value
        xrefs_data = [convf(x) for x in xrefs_data.values()]
        xrefs_data = set(xrefs_data)
        functions = [convf(x) for x in functions.values()]
        functions = set(functions)

        print(f"[!] Found {len(xrefs_data)} xrefs and {len(functions)} functions")

    except subprocess.CalledProcessError as e:
        print("[!] Error in Ghidra static analysis!")
        print(e)
        xrefs_data = {}
    
    # Save data structures
    print("[*] Saving features")
    dump(elf.v2o, str(dest_path) + "/extracted_v2o.lzma")
    dump(elf.o2v, str(dest_path) + "/extracted_o2v.lzma")
    dump(strings, str(dest_path) + "/extracted_strs.lzma")
    dump(ptrs, str(dest_path) + "/extracted_ptrs.lzma")
    dump(rptr, str(dest_path) + "/extracted_rptrs.lzma")
    dump(bm, str(dest_path) + "/extracted_btm.lzma")
    dump(xrefs_data, str(dest_path) + "/extracted_xrefs.lzma")
    dump(functions, str(dest_path) + "/extracted_functions.lzma")
    print("[*] Features saved.")

if __name__ == '__main__':
    main()
