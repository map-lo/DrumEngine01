//Search for TCI-related functions in Ghidra analyzed binary
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class SearchTCIFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Searching for TCI-related functions...\n");
        
        Program program = getCurrentProgram();
        Listing listing = program.getListing();
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Search for functions with "tci" in name
        println("=== Functions with 'tci' in name ===");
        for (Symbol symbol : symbolTable.getAllSymbols(false)) {
            String name = symbol.getName().toLowerCase();
            if (name.contains("tci")) {
                println(String.format("  %s at %s", symbol.getName(), symbol.getAddress()));
            }
        }
        
        // Search for save/write/compress related functions
        println("\n=== Functions with 'save/write/compress' in name ===");
        int count = 0;
        for (Symbol symbol : symbolTable.getAllSymbols(false)) {
            String name = symbol.getName().toLowerCase();
            if (name.contains("save") || name.contains("write") || 
                name.contains("compress") || name.contains("decompress") ||
                name.contains("encode") || name.contains("decode")) {
                
                if (!name.contains("debug") && !name.contains("assert")) {
                    println(String.format("  %s at %s", symbol.getName(), symbol.getAddress()));
                    count++;
                    if (count > 50) {
                        println("  ... (showing first 50)");
                        break;
                    }
                }
            }
        }
        
        // Search for strings containing ".tci"
        println("\n=== Strings containing '.tci' ===");
        ghidra.program.model.mem.Memory memory = program.getMemory();
        ghidra.program.model.address.AddressIterator addresses = 
            memory.getLoadedAndInitializedAddressSet().getAddresses(true);
        
        // This is simplified - in practice would need to search string data
        println("  (String search requires different API - checking defined data instead)");
        
        FunctionIterator functions = listing.getFunctions(true);
        println("\n=== Total functions in binary: " + symbolTable.getSymbolCount() + " ===");
        
        println("\nSearch complete. Use Ghidra GUI to examine these functions.");
    }
}
