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
        
        with open(self.elf_filename, "rb") as elf_fd:

            # Load the ELF in memory
            self.elf_buf = np.fromfile(elf_fd, dtype=np.byte)
            elf_fd.seek(0)

            # Parse the ELF file
            self.__read_elf_file(elf_fd)

    def __read_elf_file(self, elf_fd):
        """Parse the dump in ELF format"""
        elf_file = ELFFile(elf_fd)

        for segm in elf_file.iter_segments():
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
                    self.machine_data["Endianness"] = "little" if elf_file.header["e_ident"].EI_DATA == "ELFDATA2LSB" else "big"
                    self.machine_data["Architecture"] = "_".join(elf_file.header["e_machine"].split("_")[1:])
            else:
                # Fill arrays needed to translate physical addresses to file offsets
                r_start = segm["p_vaddr"]
                r_end = r_start + segm["p_memsz"]


                if segm["p_filesz"]:
                    p_offset = segm["p_offset"]
                    self.segments_intervals.append((r_start, r_end, p_offset, segm["p_filesz"]))
                    self.v2o_list.append((r_start, (r_end, p_offset)))
                    self.o2v_list.append((p_offset, (p_offset + (r_end - r_start), r_start)))

def extract_pointers(memory_region, pointer_size, pointer_format, valid_offset):
    valid_pointers = []
    for i in range(0, len(memory_region), pointer_size):
            # Extract pointer-sized data chunk from the memory region
            chunk = memory_region[i:i + pointer_size]
            
            # Ensure we have a full pointer-sized chunk
            if len(chunk) != pointer_size:
                continue
            
            # Unpack the chunk into an integer (pointer) using little-endian format
            pointer_value = struct.unpack(pointer_format, chunk)[0]
            
            # Check if the pointer is within the valid range
            if valid_offset[0] <= pointer_value <= valid_offset[1]:
                # Check if the pointer value is a valid index into the memory region (i.e., where it points)
                target_address = pointer_value
                #if 0 <= target_address < len(memory_region):
                    # Add the pointer and where it points
                valid_pointers.append((i, target_address))
    return valid_pointers

def read_memory_at_address(memory_region, address, offset, num_bytes):
    """
    Reads a sequence of bytes at a given address in memory.
    
    :param memory_region: A byte array representing the memory region.
    :param address: The memory address (index) to read from.
    :param num_bytes: The number of bytes to read from the address.
    :return: A byte array containing the data at the specified address.
    """
    
    address += offset
    print(hex(address))
    return memory_region[address:address + num_bytes]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dump_elf', help='Process memory dump in ELF format', type=str)
    parser.add_argument('dest_prefix', help='Prefix for the output files')
    args = parser.parse_args()

    dest_path = Path(args.dest_prefix)
    if not dest_path.exists():
        print("Destination path does not exist")
        return(1)
    # Load the ELF file and parse it
    # import time as t
    # t.sleep(15)
    print("[+] Reading ELF dump...")
    elf = ELFDump(args.dump_elf)

    #print([(hex(intervals[0]),hex(intervals[1])) for intervals in elf.segments_intervals])

    pointer_size = 4 
    pointer_format = '<I' if pointer_size == 4 else '<Q'
    
    # Loop through the memory data, reading one potential pointer at a time
    
    memory_data = elf.elf_buf
    # Extract pointers from the memory data
    ptrs = {}
    for region, i in zip(elf.segments_intervals, range(len(elf.segments_intervals))):
        print(f"[+] Searching pointers in memory region {i}...")
        valid_pointers = []
        # print(" start addr: \t" + hex(region[0]) + "\n",\
        #       "end addr:\t"   + hex(region[1]) + "\n",\
        #       "file offset:\t" + hex(region[2]) + "\n",\
        #       "file size:\t"   + hex(region[3]))
        # print("")
        # print(memory_data[region[2]:region[2]+region[3]])
        mem_region_data = memory_data[region[2]:region[2]+region[3]]
        valid_pointers.extend(extract_pointers(mem_region_data, pointer_size, pointer_format, (region[0], region[1])))
        valid_pointers.sort()
        
        n_ptrs = 0
        for pointer_address, target_address in valid_pointers:
            n_ptrs += 1
            print(f"\t ptr at 0x{region[0] + pointer_address:08X} -> 0x{target_address:08X}")
            ptrs[region[0] + pointer_address] = target_address
        print(f"[+] Found {n_ptrs} pointers in memory region {i}.")
    print(f"[+] Found {len(ptrs)} pointers in total.")
    print(f"[+] Saving extracted pointers to {str(dest_path)}/extracted_ptrs.lzma")
    dump(ptrs, str(dest_path) + "/extracted_ptrs.lzma") 
    print("[+] Done.")

if __name__ == '__main__':
    main()