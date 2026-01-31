#!/usr/bin/env python3
"""List all CInstrumentSerializer methods found in the program."""

import sys
sys.path.insert(0, '/Users/marian/Downloads/ghidra_12.0.2_PUBLIC/Ghidra/Features/PyGhidra/lib')

import pyghidra

pyghidra.start(install_dir='/Users/marian/Downloads/ghidra_12.0.2_PUBLIC')

from ghidra.program.flatapi import FlatProgramAPI

project_location = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/ghidra_analysis"
project_name = "TriggerEditor"

with pyghidra.open_project(project_location, project_name) as project:
    project_data = project.getProjectData()
    root_folder = project_data.getRootFolder()
    program_files = list(root_folder.getFiles())
    program = program_files[0].getDomainObject(project, False, False, None)

    try:
        function_manager = program.getFunctionManager()
        methods = []
        for func in function_manager.getFunctions(True):
            full_name = func.getName(True)
            if "CInstrumentSerializer" in full_name:
                methods.append((full_name, func.getEntryPoint()))

        methods.sort(key=lambda x: x[0])
        print(f"Found {len(methods)} methods:")
        for name, addr in methods:
            print(f"{addr}  {name}")
    finally:
        program.release(project)
