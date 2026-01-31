#!/usr/bin/env python3
"""Find functions by name substring."""

import sys
sys.path.insert(0, '/Users/marian/Downloads/ghidra_12.0.2_PUBLIC/Ghidra/Features/PyGhidra/lib')

import pyghidra

pyghidra.start(install_dir='/Users/marian/Downloads/ghidra_12.0.2_PUBLIC')

project_location = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/ghidra_analysis"
project_name = "TriggerEditor"

needles = ["decompressToFloatData", "CWaveData", "WaveData", "decompress"]

with pyghidra.open_project(project_location, project_name) as project:
    program = list(project.getProjectData().getRootFolder().getFiles())[0].getDomainObject(project, False, False, None)
    try:
        fm = program.getFunctionManager()
        matches = []
        for func in fm.getFunctions(True):
            name = func.getName(True)
            if any(n in name for n in needles):
                matches.append((name, func.getEntryPoint()))

        matches.sort(key=lambda x: x[0])
        print(f"Found {len(matches)} matches:")
        for name, addr in matches:
            print(f"{addr}  {name}")
    finally:
        program.release(project)
