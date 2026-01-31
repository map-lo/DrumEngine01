#!/usr/bin/env python3
"""Read constants used by CWaveData compression/decompression from Ghidra memory."""

import sys
import struct
sys.path.insert(0, '/Users/marian/Downloads/ghidra_12.0.2_PUBLIC/Ghidra/Features/PyGhidra/lib')

import pyghidra

pyghidra.start(install_dir='/Users/marian/Downloads/ghidra_12.0.2_PUBLIC')

project_location = "/Users/marian/Development/JUCE-Plugins/DrumEngine01/src/tci-reverse-engineering/ghidra_analysis"
project_name = "TriggerEditor"

ADDRESSES = {
    "DAT_10027ed54": "10027ed54",
    "_DAT_10027f5f0": "10027f5f0",
    "DAT_10027f200": "10027f200",
}

with pyghidra.open_project(project_location, project_name) as project:
    program = list(project.getProjectData().getRootFolder().getFiles())[0].getDomainObject(project, False, False, None)
    try:
        memory = program.getMemory()
        for name, addr_str in ADDRESSES.items():
            addr = program.getAddressFactory().getAddress(addr_str)
            raw = bytearray(16)
            memory.getBytes(addr, raw)
            print(f"{name} @ {addr}")
            print(f"  raw: {' '.join(f'{b:02x}' for b in raw)}")
            # Interpret as floats
            floats = struct.unpack('<4f', raw)
            print(f"  floats: {floats}")
            # Interpret as uint32
            u32 = struct.unpack('<4I', raw)
            print(f"  u32: {u32}")
    finally:
        program.release(project)
