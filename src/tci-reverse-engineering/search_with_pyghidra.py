#!/usr/bin/env python3
"""
Use PyGhidra to search for TCI-related functions in the analyzed binary.
"""

import sys
sys.path.insert(0, '/Users/marian/Downloads/ghidra_12.0.2_PUBLIC/Ghidra/Features/PyGhidra/lib')

import pyghidra

# Launch PyGhidra with Ghidra install directory
pyghidra.start(install_dir='/Users/marian/Downloads/ghidra_12.0.2_PUBLIC')

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SymbolType

# Open the project  
project_location = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/ghidra_analysis"
project_name = "TriggerEditor"

# Use the updated API
with pyghidra.open_project(project_location, project_name) as project:
    # Get the program from the project
    project_data = project.getProjectData()
    root_folder = project_data.getRootFolder()
    program_files = list(root_folder.getFiles())
    
    if not program_files:
        print("No programs found in project")
        sys.exit(1)
    
    print(f"Found {len(program_files)} program(s)")
    for pf in program_files:
        print(f"  - {pf.getName()}")
    
    # Open the program properly
    from ghidra.framework.model import DomainObject
    program = program_files[0].getDomainObject(project, False, False, None)
    
    try:
        flat_api = FlatProgramAPI(program)
        
        print("="*80)
        print("SEARCHING FOR TCI-RELATED FUNCTIONS")
        print("="*80)
        
        # Get symbol table
        symbol_table = program.getSymbolTable()
        
        # Search for TCI strings first
        print("\n1. Searching for '.tci' string references...")
        memory = program.getMemory()
        found_addresses = flat_api.findBytes(None, ".tci".encode())
        
        if found_addresses:
            print(f"   Found '.tci' at: {found_addresses}")
            # Find references to this address
            refs = flat_api.getReferencesTo(found_addresses)
            print(f"   References to '.tci': {len(list(refs))}")
            for ref in flat_api.getReferencesTo(found_addresses):
                print(f"     From: {ref.getFromAddress()}")
        
        # Search for "TRIGGER COMPRESSED INSTRUMENT" string
        print("\n2. Searching for 'TRIGGER COMPRESSED INSTRUMENT' string...")
        trigger_str = flat_api.findBytes(None, "TRIGGER COMPRESSED INSTRUMENT".encode())
        if trigger_str:
            print(f"   Found at: {trigger_str}")
            refs = flat_api.getReferencesTo(trigger_str)
            for ref in refs:
                print(f"     From: {ref.getFromAddress()}")
                func = flat_api.getFunctionContaining(ref.getFromAddress())
                if func:
                    print(f"       In function: {func.getName()}")
        
        # Search for functions with interesting names
        print("\n3. Searching for functions with save/write/compress/decompress...")
        keywords = ['save', 'write', 'compress', 'decompress', 'encode', 'decode', 'tci']
        
        interesting_functions = []
        for symbol in symbol_table.getAllSymbols(False):
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                name = symbol.getName().lower()
                for keyword in keywords:
                    if keyword in name and 'debug' not in name and 'assert' not in name:
                        interesting_functions.append((symbol.getName(), symbol.getAddress()))
                        break
        
        print(f"   Found {len(interesting_functions)} interesting functions")
        for name, addr in interesting_functions[:30]:  # Show first 30
            print(f"     {name} at {addr}")
        
        if len(interesting_functions) > 30:
            print(f"     ... and {len(interesting_functions) - 30} more")
        
        # Try to find functions that reference the 0x02bf signature
        print("\n4. Searching for references to compression signature bytes...")
        # This is the first bytes of compressed data: 02 bf 65 01
        
        print("\nSearch complete!")
        print("\nNext steps:")
        print("  1. Open Ghidra GUI: /Users/marian/Downloads/ghidra_12.0.2_PUBLIC/ghidraRun")
        print("  2. Open project: ./ghidra_analysis/TriggerEditor")
        print("  3. Navigate to the addresses found above")
        print("  4. Decompile the functions to understand the algorithm")
        
        # Let's decompile the operator() functions that reference TCI
        print("\n" + "="*80)
        print("DECOMPILING TCI-RELATED FUNCTIONS")
        print("="*80)
        
        addresses_to_check = [
            ("100111cc1", "operator() #1"),
            ("10010edce", "operator() #2"),
        ]
        
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        
        for addr_str, name in addresses_to_check:
            from ghidra.program.model.address import GenericAddress
            addr = program.getAddressFactory().getAddress(addr_str)
            func = flat_api.getFunctionContaining(addr)
            
            if func:
                print(f"\n{'='*80}")
                print(f"Function: {func.getName()} at {func.getEntryPoint()}")
                print(f"Called from: {addr}")
                print('='*80)
                
                # Decompile
                results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
                if results and results.decompileCompleted():
                    decomp = results.getDecompiledFunction()
                    if decomp:
                        code = decomp.getC()
                        # Show first 100 lines
                        lines = code.split('\n')
                        print('\n'.join(lines[:100]))
                        if len(lines) > 100:
                            remaining = len(lines) - 100
                            print(f"\n... ({remaining} more lines)")
                else:
                    print("Decompilation failed")
        
        decompiler.dispose()
        
    finally:
        program.release(project)
