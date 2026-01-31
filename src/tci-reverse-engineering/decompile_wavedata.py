#!/usr/bin/env python3
"""Decompile CWaveData compression/decompression methods."""

import sys
print("[decompile_wavedata] starting")
sys.path.insert(0, '/Users/marian/Downloads/ghidra_12.0.2_PUBLIC/Ghidra/Features/PyGhidra/lib')

import pyghidra

pyghidra.start(install_dir='/Users/marian/Downloads/ghidra_12.0.2_PUBLIC')

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

project_location = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/ghidra_analysis"
project_name = "TriggerEditor"

TARGETS = [
    "CWaveData::decompressToFloatData",
    "decompressToFloatData",
    "CWaveData::compress",
    "compress",
    "CWaveData",
]

with pyghidra.open_project(project_location, project_name) as project:
    program = list(project.getProjectData().getRootFolder().getFiles())[0].getDomainObject(project, False, False, None)
    try:
        fm = program.getFunctionManager()
        matches = []
        for func in fm.getFunctions(True):
            name = func.getName(True)
            if any(t in name for t in TARGETS):
                if "CWaveData" in name or "decompress" in name or "compress" in name:
                    matches.append(func)

        print(f"Found {len(matches)} candidate functions")

        decompiler = DecompInterface()
        decompiler.openProgram(program)

        for func in matches:
            print("=" * 80)
            print(f"{func.getName(True)} @ {func.getEntryPoint()}")
            print("=" * 80)
            results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
            if results and results.decompileCompleted():
                decomp = results.getDecompiledFunction()
                if decomp:
                    print(decomp.getC())
            else:
                print("Decompilation failed")

        decompiler.dispose()
    finally:
        program.release(project)
#!/usr/bin/env python3
"""Decompile CWaveData compression/decompression methods."""

import sys
sys.path.insert(0, '/Users/marian/Downloads/ghidra_12.0.2_PUBLIC/Ghidra/Features/PyGhidra/lib')

import pyghidra

pyghidra.start(install_dir='/Users/marian/Downloads/ghidra_12.0.2_PUBLIC')

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

project_location = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/ghidra_analysis"
project_name = "TriggerEditor"

TARGETS = [
    "CWaveData::decompressToFloatData",
    "decompressToFloatData",
    "CWaveData::compress",
    "compress",
    "CWaveData",
]

with pyghidra.open_project(project_location, project_name) as project:
    program = list(project.getProjectData().getRootFolder().getFiles())[0].getDomainObject(project, False, False, None)
    try:
        fm = program.getFunctionManager()
        matches = []
        for func in fm.getFunctions(True):
            name = func.getName(True)
            if any(t in name for t in TARGETS):
                if "CWaveData" in name or "decompress" in name or "compress" in name:
                    matches.append(func)

        print(f"Found {len(matches)} candidate functions")

        decompiler = DecompInterface()
        decompiler.openProgram(program)
