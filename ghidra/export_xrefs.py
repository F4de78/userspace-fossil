from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.block import SimpleBlockModel
from ghidra.util.task import TaskMonitor
from ghidra.program.model.listing import Instruction
import json
import ctypes
"""
This script exports cross-references (xrefs) and function entry points from a Ghidra program to a JSON file.
The script performs the following steps:
1. Retrieves the output filename from the script arguments.
2. Initializes the current program and a SimpleBlockModel for basic block analysis.
3. Iterates over all symbols in the program's symbol table to identify valid symbols that:
    - Are of type LABEL.
    - Have a memory address.
    - Have references.
    - Are not instructions.
    - Are contained within code blocks that have either sources or destinations.
4. Collects these valid symbols and their addresses.
5. Iterates over all functions in the program to collect their entry points.
6. Dumps the collected symbols and functions into a JSON file specified by the output filename.
Args:
     None (script arguments are retrieved using getScriptArgs()).
Raises:
     SystemExit: If the output filename is not provided in the script arguments.
Output:
     A JSON file containing two dictionaries:
     - valid_symbols: A dictionary mapping symbol names to their addresses.
     - functions: A dictionary mapping function names to their entry points.
"""

args = getScriptArgs()
if len(args) < 1:
    exit(1)
out_filename = args[0]

program = getCurrentProgram()
bbm = SimpleBlockModel(program)
valid_symbols = {}
functions = {}

st = program.getSymbolTable()
for symbol in st.getAllSymbols(True):
    
    if symbol.getSymbolType() == SymbolType.LABEL and symbol.getAddress().isMemoryAddress() and symbol.hasReferences():
        if isinstance(symbol.getObject(), Instruction):
            continue

        for reference in symbol.getReferences(): 
            block = bbm.getCodeBlocksContaining(reference.getFromAddress(), TaskMonitor.DUMMY)[0]
            if block.getNumDestinations(TaskMonitor.DUMMY) or block.getNumSources(TaskMonitor.DUMMY):
                break
        else:
            continue
    
        valid_symbols[symbol.getName()] = symbol.getAddress().getUnsignedOffset()

fm = program.getFunctionManager()
funcs = fm.getFunctions(True)
for func in funcs: 
    functions[func.getName()] = func.getEntryPoint().getUnsignedOffset()


json.dump((valid_symbols, functions), open(out_filename, "w"))


