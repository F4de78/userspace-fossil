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
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import NoteSegment
import struct

class ELFDump:
    def __init__(self, elf_filename):
        self.filename = elf_filename
        self.machine_data = {}
        self.v2o = None   # Virtual to RAM (ELF offset)
        self.o2v = None   # RAM (ELF offset) to Physical
        self.v2o_list = []   # Physical to RAM (ELF offset)
        self.o2v_list = []   # RAM (ELF offset) to Physical
        self.elf_buf = np.zeros(0, dtype=np.byte)
        self.elf_filename = elf_filename
        self.segments_intervals = []
        self.elf_file = None
        
        with open(self.elf_filename, "rb") as elf_fd:

            # Load the ELF in memory
            self.elf_buf = np.fromfile(elf_fd, dtype=np.byte)
            elf_fd.seek(0)

            # Parse the ELF file
            self.__read_elf_file(elf_fd)

    def __read_elf_file(self, elf_fd):
        """Parse the dump in ELF format"""
        self.elf_file = ELFFile(elf_fd)

        for segm in self.elf_file.iter_segments():
            # NOTES
            if isinstance(segm, NoteSegment):
                for note in segm.iter_notes():

                    # Ignore NOTE genrated by other softwares
                    if note["n_name"] != "FOSSIL":
                        continue

                    # At moment only one type of note
                    if note["n_type"] != 0xdeadc0de:
                        continue

                    # Suppose only one deadcode note
                    self.machine_data = json.loads(note["n_desc"].strip(b'\x00')) #fix: removes trailing \x00
                    self.machine_data["Endianness"] = "little" if self.elf_file.header["e_ident"].EI_DATA == "ELFDATA2LSB" else "big"
                    self.machine_data["Architecture"] = "_".join(self.elf_file.header["e_machine"].split("_")[1:])
            else:
                # Fill arrays needed to translate physical addresses to file offsets
                r_start = segm["p_vaddr"]
                r_end = r_start + segm["p_memsz"]


                if segm["p_filesz"]:
                    p_offset = segm["p_offset"]
                    self.segments_intervals.append((r_start, r_end, p_offset, segm["p_filesz"]))
                    self.v2o_list.append((r_start, (r_end, p_offset)))
                    self.o2v_list.append((p_offset, (p_offset + (r_end - r_start), r_start)))

def extract_pointers(segments, memory_region, pointer_size, pointer_format, valid_offset, offset):
    valid_pointers = []
    for i in range(0, len(memory_region), pointer_size):
        # Extract pointer-sized data chunk from the memory region
        chunk = memory_region[i:i + pointer_size]
        
        # Ensure we have a full pointer-sized chunk
        if len(chunk) != pointer_size:
            continue

        # check if pointer is aligned
        if i % pointer_size != 0:
            continue
        
        # Unpack the chunk into an integer (pointer) using little-endian format
        pointer_value = struct.unpack(pointer_format, chunk)[0]

        for start, end, _, _ in segments:
            if start <= pointer_value <= end:        
                valid_pointers.append((offset + i, pointer_value))
    return valid_pointers

def save_pointers(segments_intervals:list, pointer_size:int, pointer_format:str, memory_data:bytes):
    ptrs = {}
    for region, i in zip(segments_intervals, range(len(segments_intervals))):
        print(f"[+] Searching pointers in memory region {i}...")
        valid_pointers = []
        # print(" start addr: \t" + hex(region[0]) + "\n",\
        #       "end addr:\t"   + hex(region[1]) + "\n",\
        #       "file offset:\t" + hex(region[2]) + "\n",\
        #       "file size:\t"   + hex(region[3]))
        # print("")
        # print(memory_data[region[2]:region[2]+region[3]])
        mem_region_data = memory_data[region[2]:region[2]+region[3]]
        valid_pointers.extend(extract_pointers(segments_intervals, mem_region_data, pointer_size, pointer_format, (region[0], region[1]), region[0]))
        valid_pointers.sort()
        n_ptrs = 0
        for pointer_address, target_address in valid_pointers:
            n_ptrs += 1
            print(f"\t ptr at 0x{pointer_address:08X} -> 0x{target_address:08X}")
            ptrs[pointer_address] = target_address
        print(f"[+] Found {n_ptrs} pointers in memory region {i}.")
    #revertse pointers
    rptrs = {v: k for k, v in ptrs.items()}
    return ptrs,rptrs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dump_elf', help='Process memory dump in ELF format', type=str)
    parser.add_argument('dest_prefix', help='Prefix for the output files')
    args = parser.parse_args()

    dest_path = Path(args.dest_prefix)
    if not dest_path.exists():
        print("Destination path does not exist")
        return(1)

    print("[+] Reading ELF dump...")
    elf = ELFDump(args.dump_elf)

    #print([(hex(intervals[0]),hex(intervals[1])) for intervals in elf.segments_intervals])

    arch = elf.elf_file.get_machine_arch()
    if arch == "x86":
        pointer_size = 4
    elif arch == "x64":
        pointer_size = 8
    else:
        print("Architecture not yet supported")
        return(1)
    pointer_format = '<I' if pointer_size == 4 else '<Q'
    memory_data = elf.elf_buf

    # Extract pointers from the memory data
    ptrs ,ptrs = save_pointers(elf.segments_intervals, pointer_size, pointer_format, memory_data)
    # create reverse pointers dictionary
    rptrs = {v: k for k, v in ptrs.items()}
    
    # print pointer dictionary in hex
    print(f"[+] Found {len(ptrs)} pointers in total.")
    print(f"[+] Saving extracted pointers to {str(dest_path)}/extracted_ptrs.lzma")
    dump(ptrs, str(dest_path) + "/extracted_ptrs.lzma") 
    print("[+] Done.")
    return ptrs,rptrs

if __name__ == '__main__':
    main()