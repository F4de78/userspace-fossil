#!/usr/bin/env python3

from signal import signal, SIGINT
import argparse
from datetime import datetime
from pygdbmi.gdbcontroller import GdbController, DEFAULT_GDB_LAUNCH_COMMAND
import os
import errno
import pickle
import re
import json
import shutil
import threading
from pprint import pprint

start_time_g = 0
qemu_monitor = None
gdbmi = None
little_endian = False
dump_fifo = None
path = None
custom_values = []

def dump_process(pid: int):
    global start_time_g
    global qemu_monitor
    global gdbmi
    global dump_fd
    global dump_fifo
    global cpu_dump_fd

    uptime = 0 # patch
    print("\n\n[+] Stop process, save registers and dump memory")

    # Create ELF header
    gdbmi = GdbController()
    # attach to running process
    
    print(f"[+] Attaching to process {pid}")
    resp = gdbmi.write(f"attach {pid}")
    architecture = resp[-1].get("payload").get("frame").get("arch")
    if 'x86-64' in architecture:
        architecture = 'x86_64'
    print(f"[!] Architecture: {architecture}")
    little_endian = True if "little" in gdbmi.write("show endian")[1]["payload"] else False
    print(f"[!] Endianness: {'little' if little_endian else 'big'}")

    # Dump registers
    gdbmi.write('help') # Workaround
    gdb_reg_reply = gdbmi.write('info all-registers') # get all registers
    registers = extract_registers_values(gdb_reg_reply)
    print("[!] Registers:")
    pprint(registers)

    # put architecture, endianness and registers to json object
    cpu_values = {
        "architecture": architecture,
        "endianness": "little" if little_endian else "big",
        "registers": registers
    }

    cpu_dump_fd.write(json.dumps(cpu_values))


    # used for dynamic analysis later    
    core_dump_out = gdbmi.write("gcore "+path+"core.elf")

    # Unfreeze the machine and close monitors
    gdbmi.exit()
    print("Done!")
    exit(0)


def extract_registers_values(gdb_message):
    regs = {}
    expr = re.compile(r"(?P<reg>\w+)\s+(?P<value>0x[0-9a-fA-F]+).+")
    for msg in gdb_message:

        if msg["message"] == "done":
            continue

        parsed_payload = expr.fullmatch(msg["payload"].strip())
        if parsed_payload:
            regs[parsed_payload.group("reg")] = int(parsed_payload.group("value"), 16)

    return regs

def main():
    global start_time_g
    global qemu_monitor
    global gdbmi
    global dump_fd
    global cpu_dump_fd
    global little_endian
    global path
    global custom_values

    parser = argparse.ArgumentParser(description='Process and registers dumper')
    parser.add_argument("-filename_procdata", help="Prefix for CPU data of core dump file.", type=str)
    parser.add_argument("-pid", help="PID of the running process", type=int)
    args = parser.parse_args()

    # Create dump file
    try:
        cpu_dump_fd = open(args.filename_procdata, "w")
    except Exception as e:
        print(e)
        print("Unable to open  output file!")
        exit(1)
    
    path = os.path.dirname(os.path.abspath(args.filename_procdata)) + "/"
    

    dump_process(args.pid)


if __name__ == "__main__":
    main()