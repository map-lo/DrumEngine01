#!/usr/bin/env python3
"""Decompile functions referencing the TCI signature string."""

import sys
sys.path.insert(0, '/Users/marian/Downloads/ghidra_12.0.2_PUBLIC/Ghidra/Features/PyGhidra/lib')

import pyghidra

pyghidra.start(install_dir='/Users/marian/Downloads/ghidra_12.0.2_PUBLIC')

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import StringDataType

project_location = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/ghidra_analysis"
project_name = "TriggerEditor"

TARGET = "TRIGGER COMPRESSED INSTRUMENT"

with pyghidra.open_project(project_location, project_name) as project:
    program = list(project.getProjectData().getRootFolder().getFiles())[0].getDomainObject(project, False, False, None)
    try:
        listing = program.getListing()
        memory = program.getMemory()

        # Find the string in memory by raw byte search
        target_addr = None
        target_bytes = TARGET.encode("utf-8")

        for block in memory.getBlocks():
            if not block.isInitialized():
                continue
            try:
                block_bytes = bytearray(block.getSize())
                memory.getBytes(block.getStart(), block_bytes)
            except Exception:
                continue

            idx = block_bytes.find(target_bytes)
            if idx != -1:
                target_addr = block.getStart().add(idx)
                break

        if not target_addr:
            print("Target string not found via memory scan. Falling back to known address.")
            target_addr = program.getAddressFactory().getAddress("1003b836d")

        print(f"Found string at {target_addr}")

        # Find references to the string
        refs = program.getReferenceManager().getReferencesTo(target_addr)
        funcs = {}
        fm = program.getFunctionManager()
        for ref in refs:
            func = fm.getFunctionContaining(ref.getFromAddress())
            if func:
                funcs[func.getEntryPoint()] = func

        if not funcs:
            print("No referencing functions found.")
            raise SystemExit(1)

        decompiler = DecompInterface()
        decompiler.openProgram(program)

        for entry, func in funcs.items():
            print("=" * 80)
            print(f"Function: {func.getName(True)} @ {entry}")
            print("=" * 80)
            results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
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
