#!/usr/bin/env python3
"""
Ghidra headless script to find TCI save/compression functions.
Run after analysis completes.
"""

# Search for TCI-related strings and find their references
from ghidra.program.model.symbol import SymbolType

# Get current program
program = currentProgram
listing = program.getListing()
memory = program.getMemory()
symbol_table = program.getSymbolTable()

print("\n" + "="*80)
print("Searching for TCI-related functions...")
print("="*80)

# Search for strings
search_strings = [
    ".tci",
    "TCI",
    "TRIGGER COMPRESSED INSTRUMENT",
    "Select trigger instrument file to save",
    "compressed data"
]

found_addresses = []

for search_str in search_strings:
    print(f"\nSearching for: '{search_str}'")
    
    # Search memory for the string
    addr = memory.getMinAddress()
    while addr is not None:
        found = memory.findBytes(addr, search_str.encode('utf-8'), None, True, monitor)
        if found is None:
            break
        
        print(f"  Found at: {found}")
        found_addresses.append(found)
        
        # Find references to this address
        refs = getReferencesTo(found)
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = getFunctionContaining(from_addr)
            if func:
                print(f"    Referenced by function: {func.getName()} at {from_addr}")
        
        # Continue search
        addr = found.add(1)
        if addr.compareTo(memory.getMaxAddress()) > 0:
            break

print("\n" + "="*80)
print("Searching symbol table for save/write functions...")
print("="*80)

keywords = ["save", "write", "export", "tci", "compress", "encode"]
for keyword in keywords:
    print(f"\nKeyword: '{keyword}'")
    symbols = symbol_table.getSymbols(keyword.lower())
    count = 0
    for symbol in symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            print(f"  {symbol.getName()} at {symbol.getAddress()}")
            count += 1
            if count >= 10:
                print(f"  ... (showing first 10)")
                break

print("\n" + "="*80)
print("Done!")
print("="*80)
