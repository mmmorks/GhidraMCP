package com.lauriewired.mcp.utils;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.Iterator;

/**
 * Utility methods for Ghidra operations in GhidraMCP
 */
public class GhidraUtils {

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    public static Function getFunctionForAddress(Program program, Address addr) {
        if (program == null || addr == null) {
            return null;
        }
        
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Find a high symbol by name in the given high function
     */
    public static HighSymbol findVariableByName(HighFunction highFunction, String variableName) {
        if (highFunction == null || variableName == null) {
            return null;
        }
        
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    public static DecompileResults decompileFunction(Function func, Program program) {
        if (func == null || program == null) {
            return null;
        }
        
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation
        
        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
        
        if (results == null || !results.decompileCompleted()) {
            Msg.error(GhidraUtils.class, "Could not decompile function: " + 
                     (results != null ? results.getErrorMessage() : "Unknown error"));
            return null;
        }
        
        return results;
    }

    /**
     * Get the address of a symbol by name
     */
    public static Address getSymbolAddress(Program program, String symbolName) {
        if (program == null || symbolName == null || symbolName.isEmpty()) {
            return null;
        }
        
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbolIterator = symbolTable.getSymbols(symbolName);
        
        if (symbolIterator.hasNext()) {
            // Use the first matching symbol's address
            Symbol symbol = symbolIterator.next();
            return symbol.getAddress();
        }
        
        return null;
    }
    
    /**
     * Check if full commit is required for function prototype changes
     * 
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
     * 
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	public static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		ghidra.program.model.listing.Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			ghidra.program.model.listing.VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}
}
