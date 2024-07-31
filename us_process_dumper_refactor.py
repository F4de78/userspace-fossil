#!/usr/bin/env -S python3 -u

import argparse
import errno
import json
import os
import re
import shutil
import threading
from datetime import datetime
from io import BufferedWriter
from pygdbmi.gdbcontroller import GdbController, DEFAULT_GDB_LAUNCH_COMMAND
from qmp import QEMUMonitorProtocol
from typing import Any

data_keys = [
    'qmp_service', 'gdb_service', 'dump_path', 'custom_values', 'host_data_path',
    'dump_file_path', 'dump_file_descriptor', 'qemu_qmp_monitor', 'gdb_controller',
    'start_time_gdb', 'is_little_endian'
]

def parse_arguments() -> dict:
    parser = argparse.ArgumentParser(description='You have to call QEMU with "-qmp tcp:HOST:PORT,server -s" options')
    parser.add_argument("path", help="Path for the output", type=str)
    parser.add_argument("pid", help="PID of the running process", type=int)
    args = parser.parse_args()

    return {
        'dump_path': args.path,
        'gdb_service': args.pid
    }

def get_qemu_qmp_monitor(qmp_service:dict) -> QEMUMonitorProtocol:
    try:
        monitor = QEMUMonitorProtocol(tuple(qmp_service.values()))
        monitor.connect()
    except Exception as exception:
        print(f'[Error] An error occured while trying to create the Qemu QMP monitor!\nError details: {exception}\nExiting...')
        exit(5)
    print('Qemu QMP connected!')
    return monitor

def get_gdb_controller(gdb_service:str) -> GdbController:
    try:
        gdbmi = GdbController(DEFAULT_GDB_LAUNCH_COMMAND)
        gdbmi.write(f'target remote {gdb_service}')
    except Exception as exception:
        print(f'[Error] An error occured while trying to create the GDB controller!\nError details: {exception}\nExiting...')
        exit(8)
    return gdbmi

def check_arguments(args:dict) -> dict:
    # Check docker usage and output dump path
    args['dump_path'] = os.path.join(args['dump_path'],'')
    args['gdb_controller'] = get_gdb_controller(args['gdb_service'])
    args['is_little_endian'] = 'little' in args['gdb_controller'].write('show endian')[1]['payload']


    return args

def wait_for_interrupt() -> None:
    while(True):
        try:
            input()
        except KeyboardInterrupt:
            break

def create_elf_header(architecture:str, is_little_endian:bool) -> bytearray:
    """Creates the main ELF header """

    endianness = 'little' if is_little_endian else 'big'
    
    # Get architecture code
    if architecture == 'aarch64':
        architecture_code = 0xB7
    elif architecture == 'arm':
        architecture_code = 0x28
    elif architecture == 'riscv32':
        architecture_code = 0xF3
    elif architecture == 'riscv64':
        architecture_code = 0xF3
    elif architecture == 'x86_64':
        architecture_code = 0x3E
    elif architecture == 'i386':
        architecture_code = 0x03
    else:
        print('[Error] Couldn\'t recognize the machine architecture! Exiting...')
        exit(10)

    # Compile the header
    elf_header_size = 0x40
    elf_header = bytearray(elf_header_size)
    elf_header[0x00:0x04] = b'\x7fELF'                                   # Magic
    elf_header[0x04] = 2                                                 # Elf type
    elf_header[0x05] = 1 if is_little_endian else 2                      # Endianness
    elf_header[0x06] = 1                                                 # Version
    elf_header[0x10:0x12] = 0x4.to_bytes(2, endianness)                  # elf_type_code
    elf_header[0x12:0x14] = architecture_code.to_bytes(2, endianness)    # architecture_code
    elf_header[0x14:0x18] = 0x1.to_bytes(4, endianness)                  # version_code
    elf_header[0x34:0x36] = elf_header_size.to_bytes(2, endianness)      # elf_header_size

    return elf_header

def extract_registers_values(messages:list[dict[str, str]]) -> dict[str, int]:
    registers = {}
    regex = re.compile(r"(?P<reg>\w+)\s+(?P<value>0x[0-9a-fA-F]+).+")

    for message in messages:
        if message["message"] == "done":
            continue
        parsed_payload = regex.fullmatch(message["payload"].strip())
        if parsed_payload:
            registers[parsed_payload.group("reg")] = int(parsed_payload.group("value"), 16)

    return registers

def split_memory_tree_data(memory_tree:str) -> list[dict[str, str|int]]:
    """
    Splits memory data into a list of memory regions
    Returns a list of dictionaries with the following keys:
    - 'start': region starting address
    - 'end'  : region ending address
    - 'type' : region type
    - 'name' : region name
    """

    # Get the starting line index for getting interesting data
    start_index = -1
    lines = memory_tree.split("\r\n")
    for index, line in enumerate(lines):
        if line.strip() == "Root memory region: system":
            start_index = index
            break

    if start_index == -1:
        print('[Error] Could not find interesting data while splitting the memory tree data! Exiting...')
        exit(12)

    # Retrieve regions
    regions = []
    regex = re.compile(r"\s*(?P<r_start>[0-9abcdef]{1,})-(?P<r_end>[0-9abcdef]{1,})\s+\(prio\s+-?\d+,\s+(?P<r_type>.+)\):\s+(?P<r_name>.+)")

    for line in lines[start_index:]:
        if not line:
            break
        parsed_line = regex.fullmatch(line)
        if not parsed_line:
            continue

        # Get region name
        region_name = parsed_line.group("r_name")
        if "@" in region_name and "ram" in region_name:
            region_name =  "ram"

        # Append the region
        regions.append({
            'start': int(parsed_line.group("r_start"), 16), # Region starting address
            'end': int(parsed_line.group("r_end"), 16),     # Region ending address
            'type': parsed_line.group("r_type"),            # Region type
            'name': region_name                             # Region name
        })

    return regions

def create_machine_note(is_little_endian:bool, note_name:str, note_description:Any, note_type_code:int) -> bytes:
    """
    Returns the machine note as bytes.   
    The fields are ordered as follows:
    - Note name size
    - Note description size
    - Note type code
    - Note name
    - Note description
    """

    # Define size and endianness
    field_size = 4
    endianness = 'little' if is_little_endian else 'big'

    # Serialize description and get paddings
    serialized_description = json.dumps(note_description)
    name_padding = (1 + field_size - ((len(note_name)+1) % field_size))
    description_padding = (1 + field_size - ((len(serialized_description)+1) % field_size))

    # Create fields: name_size, description_size, type, name, description
    name_size_field = (len(note_name)+1).to_bytes(field_size, endianness)
    description_size_field = (len(serialized_description)+1).to_bytes(field_size, endianness)
    type_field = note_type_code.to_bytes(field_size, endianness)
    name_field = note_name.encode() + b'\x00'*name_padding
    description_field = serialized_description.encode() + b'\x00'*description_padding

    return name_size_field + \
        description_size_field + \
        type_field + \
        name_field + \
        description_field

def create_program_header(elf_header:bytearray, memory_regions:list[dict], is_little_endian:bool, note_length:int) -> tuple[bytearray, bytearray]:
    """ 
    Returns two bytearrays representing the completed elf header and machine data
    The machine data is as follows:
    - Note
        - Type
        - Offset
        - Size
    - Memory regions (foreach)
        - Type
        - Flags
        - Offset
        - Virtual address
        - Physical address
        - Size
    """
    
    # Define working data
    endianness = 'little' if is_little_endian else 'big'
    program_header = bytearray()
    header_field_size = 0x38
    program_header_offset = len(elf_header) + (len(memory_regions) + 1) * header_field_size

    # Create note entry
    note_entry = bytearray(header_field_size)
    note_entry[0x00:0x04] = 0x4.to_bytes(4, endianness)                         # Program type
    note_entry[0x08:0x10] = program_header_offset.to_bytes(8, endianness)       # Program offset
    note_entry[0x20:0x28] = note_length.to_bytes(8, endianness)                 # Program file size
    
    program_header_offset += note_length
    program_header += note_entry

    # Create memory entries
    for memory_region in memory_regions:
        region_file_size = memory_region['end'] - memory_region['start'] + 1

        region_entry = bytearray(header_field_size)
        region_entry[0x00:0x04] = 0x1.to_bytes(4, endianness)                             # Program type
        if memory_region['type'] == 'rom':                                                # Program flags
            region_entry[0x04:0x08] = 0x5.to_bytes(4, endianness)
        elif memory_region['type'] != 'ram':
            region_entry[0x04:0x08] = 0x6.to_bytes(4, endianness)
        else:
            region_entry[0x04:0x08] = 0x7.to_bytes(4, endianness)
        region_entry[0x08:0x10] = program_header_offset.to_bytes(8, endianness)           # Program offset
        region_entry[0x10:0x18] = memory_region['start'].to_bytes(8, endianness)          # Program virtual address
        region_entry[0x18:0x20] = memory_region['start'].to_bytes(8, endianness)          # Program phisycal address
        if memory_region['type'] == 'ram':
            region_entry[0x20:0x28] = region_file_size.to_bytes(8, endianness)            # Program file size
            program_header_offset += region_file_size
        region_entry[0x28:0x30] = region_file_size.to_bytes(8, endianness)                # Program memory size

        program_header += region_entry

    # Complete ELF header
    elf_header[0x20:0x28] = 0x40.to_bytes(8, endianness)                       
    elf_header[0x36:0x38] = header_field_size.to_bytes(2, endianness)
    elf_header[0x38:0x3A] = (len(memory_regions) + 1).to_bytes(2, endianness)

    return elf_header, program_header

def dump_header(gdb_controller:GdbController, is_little_endian:bool, custom_values:list[str], dump_file_descriptor:BufferedWriter) -> list[dict]:
    """ 
    Retrieves machine data and dumps it in the output file
    Returns memory regions
    """
    uptime = 0
    # Get the architecture
    resp = gdb_controller.write(f"attach {arguments.pid}")
    architecture = resp[-1].get("payload").get("frame").get("arch")
    if 'x86-64' in architecture:
        architecture = 'x86_64'
    assert isinstance(architecture, str)

    # Dump registers
    gdb_controller.write('help')
    registers_reply = gdb_controller.write('info all-registers')
    registers = extract_registers_values(registers_reply)

    # Retrieve memory regions
    gdb_reg_reply = gdb_controller.write('info proc mappings') # get all registers
    mem_regions = []
    for i in range (4, len(gdb_reg_reply)-1):
        mem_region_line = gdb_reg_reply[i].get("payload").split()[1:]
        if len(mem_region_line) < 5:
            mem_region_line.append("[?]")
        region = {
            "start": int(mem_region_line[0],16),
            "end": int(mem_region_line[1],16),
            "type": "ram", # since we are dumping the memory of a process
            "name": mem_region_line[4] # not sure if this is the name
        }
        mem_regions.append(region)

    memory_regions_data = []
    for x in mem_regions:
        memory_regions_data.append((x['start'], x['name']))

    machine_data = {
        'Architecture': architecture,
        'Uptime': uptime,
        'CPURegisters': registers,
        'MemoryMappedDevices': memory_regions_data
    }

    # Add custom values
    keys = ['context','key','value']
    for custom_value in custom_values:
        register = dict(zip(keys, custom_value.split(':')))
        if len(register) != 3:
            continue
        try:
            int(register['value'],0)
        except:
            continue

        if register['context'] not in machine_data:
            machine_data[register['context']] = dict()
        machine_data[register['context']][register['key']] = int(register['value'],0)
    
    # Create machine note
    machine_note = create_machine_note(is_little_endian, 'FOSSIL', machine_data, 0xDEADC0DE)

    # Create the main elf header
    elf_header = create_elf_header(architecture, is_little_endian)

    # Create program header
    elf_header, program_header = create_program_header(elf_header, memory_regions, is_little_endian, len(machine_note))

    # Write headers
    dump_file_descriptor.write(elf_header + program_header + machine_note)

    return memory_regions

def call_program_memory_save(qmp_monitor:QEMUMonitorProtocol, region_start:int, region_size:int, dump_path:str) -> None:
    qmp_monitor.cmd('pmemsave', {
        'val': region_start,
        'size': region_size,
        'filename': os.path.join(dump_path, 'dump_fifo')
    })

def dump_memory_regions(memory_regions:list[dict], qmp_monitor:QEMUMonitorProtocol, dump_path:str, dump_file_descriptor:BufferedWriter) -> None:
    for region in memory_regions:
        if region['type'] != 'ram':
            continue
        region_size = region['end'] - region['start'] + 1
        
        thread = threading.Thread(target=call_program_memory_save, args=(qmp_monitor, region['start'], region_size, dump_path))
        thread.start()
        fifo_file_descriptor = open(os.path.join(dump_path, 'dump_fifo'), 'rb')
        shutil.copyfileobj(fifo_file_descriptor, dump_file_descriptor)
        thread.join()

        fifo_file_descriptor.close()

def clean_up(dump_file_descriptor:BufferedWriter, qmp_monitor:QEMUMonitorProtocol, gdb_controller:GdbController, dump_path:str) -> None:
    dump_file_descriptor.close()

    qmp_monitor.cmd('cont', {})
    qmp_monitor.close()

    gdb_controller.exit()

    try:
        os.remove(os.path.join(dump_path, 'dump_fifo'))
    except FileNotFoundError:
        pass

if __name__ == "__main__":

    # Arguments parsing and checking
    arguments = check_arguments(parse_arguments())

    # Get and process data
    uptime = 0
    print('Save registers and dump memory')
    
    memory_regions = dump_header(
        arguments['gdb_controller'],
        arguments['is_little_endian'],
        uptime,
    )
    dump_memory_regions(
        memory_regions, 
        arguments['qemu_qmp_monitor'],
        arguments['dump_path'],
        arguments['dump_file_descriptor']
    )
    clean_up(
        arguments['dump_file_descriptor'],
        arguments['qemu_qmp_monitor'],
        arguments['gdb_controller'],
        arguments['dump_path']
    )
    print("Done!")
    exit(0)