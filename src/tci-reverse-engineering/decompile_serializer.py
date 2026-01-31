#!/usr/bin/env python3
"""
Decompile CInstrumentSerializer methods to understand TCI format.
"""

import sys
sys.path.insert(0, '/Users/marian/Downloads/ghidra_12.0.2_PUBLIC/Ghidra/Features/PyGhidra/lib')

import pyghidra

# Launch PyGhidra with Ghidra install directory
pyghidra.start(install_dir='/Users/marian/Downloads/ghidra_12.0.2_PUBLIC')

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Open the project  
project_location = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/ghidra_analysis"
project_name = "TriggerEditor"

with pyghidra.open_project(project_location, project_name) as project:
    project_data = project.getProjectData()
    root_folder = project_data.getRootFolder()
    program_files = list(root_folder.getFiles())
    
    program = program_files[0].getDomainObject(project, False, False, None)
    
    try:
        flat_api = FlatProgramAPI(program)
        
        print("="*80)
        print("DECOMPILING CInstrumentSerializer METHODS")
        print("="*80)
        
        # Methods to decompile (by name patterns)
        target_names = [
            "CInstrumentSerializer::putLong",
            "CInstrumentSerializer::getLong",
            "CInstrumentSerializer::putFloatRecord",
            "CInstrumentSerializer::getFloat",
            "putLong",
            "getLong",
            "putFloatRecord",
            "getFloat",
        ]
        
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        
        function_manager = program.getFunctionManager()
        matched = {}

        # Scan functions by name for matches
        for func in function_manager.getFunctions(True):
            name = func.getName()
            full_name = func.getName(True)
            for target in target_names:
                if target in name or target in full_name:
                    matched[target] = func

        if not matched:
            print("No matching CInstrumentSerializer methods found by name.")
        else:
            for target, func in matched.items():
                print(f"\n{'='*80}")
                print(f"Method match: {target} -> {func.getName(True)} at {func.getEntryPoint()}")
                print('='*80)

                results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
                if results and results.decompileCompleted():
                    decomp = results.getDecompiledFunction()
                    if decomp:
                        code = decomp.getC()
                        print(code)
                else:
                    print("Decompilation failed")
        
        decompiler.dispose()
        
    finally:
        program.release(project)

print("\nDone!")
