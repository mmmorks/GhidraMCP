package com.lauriewired.mcp.utils;

import com.lauriewired.mcp.model.response.FunctionCodeResult;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Utility methods for Ghidra operations in GhidraMCP
 */
public class GhidraUtils {

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    public static Function getFunctionForAddress(final Program program, final Address addr) {
        if (program == null || addr == null) {
            return null;
        }
        
        return Optional.ofNullable(program.getFunctionManager().getFunctionAt(addr))
            .orElseGet(() -> program.getFunctionManager().getFunctionContaining(addr));
    }

    /**
     * Find a high symbol by name in the given high function
     */
    public static HighSymbol findVariableByName(final HighFunction highFunction, final String variableName) {
        if (highFunction == null || variableName == null) {
            return null;
        }
        
        return iteratorToStream(highFunction.getLocalSymbolMap().getSymbols())
            .filter(symbol -> symbol.getName().equals(variableName))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Helper method to convert an Iterator to a Stream
     */
    private static <T> Stream<T> iteratorToStream(final Iterator<T> iterator) {
        return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED),
            false
        );
    }

    /**
     * Decompile a function and return the results
     */
    public static DecompileResults decompileFunction(final Function func, final Program program) {
        if (func == null || program == null) {
            return null;
        }
        
        // Set up decompiler for accessing the decompiled function
        final var decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation
        
        // Decompile the function
        final var results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
        
        if (results == null || !results.decompileCompleted()) {
            Msg.error(GhidraUtils.class, "Could not decompile function: " + 
                     Optional.ofNullable(results)
                         .map(DecompileResults::getErrorMessage)
                         .orElse("Unknown error"));
            return null;
        }
        
        return results;
    }

    /**
     * Extract structured {address: code} lines from decompile results.
     * Uses PrettyPrinter/ClangToken markup when available, falls back to plain text splitting.
     *
     * @return list of single-entry maps, or empty list if decompilation failed
     */
    public static List<Map<String, String>> extractDecompiledLines(final DecompileResults result, final Function func) {
        if (result == null || !result.decompileCompleted()) {
            return List.of();
        }

        final ClangTokenGroup markup = result.getCCodeMarkup();
        if (markup == null) {
            final List<Map<String, String>> lines = new ArrayList<>();
            for (final String line : result.getDecompiledFunction().getC().split("\n", -1)) {
                lines.add(FunctionCodeResult.line(null, line));
            }
            return lines;
        }

        final PrettyPrinter printer = new PrettyPrinter(func, markup, null);
        final List<Map<String, String>> lines = new ArrayList<>();
        for (final ClangLine line : printer.getLines()) {
            Address lineAddr = null;
            for (final ClangToken token : line.getAllTokens()) {
                lineAddr = token.getMinAddress();
                if (lineAddr != null) break;
            }
            lines.add(FunctionCodeResult.line(
                    lineAddr != null ? lineAddr.toString() : null,
                    PrettyPrinter.getText(line)));
        }
        return lines;
    }

    /**
     * Get the address of a symbol by name
     */
    public static Address getSymbolAddress(final Program program, final String symbolName) {
        if (program == null || symbolName == null || symbolName.isEmpty()) {
            return null;
        }
        
        final var symbolTable = program.getSymbolTable();
        final var symbolIterator = symbolTable.getSymbols(symbolName);
        
        return Optional.of(symbolIterator)
            .filter(SymbolIterator::hasNext)
            .map(SymbolIterator::next)
            .map(Symbol::getAddress)
            .orElse(null);
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
    public static boolean checkFullCommit(final HighSymbol highSymbol, final HighFunction hfunction) {
        // Early return if this isn't a parameter
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        
        final var function = hfunction.getFunction();
        final var parameters = function.getParameters();
        final var localSymbolMap = hfunction.getLocalSymbolMap();
        final var numParams = localSymbolMap.getNumParams();
        
        // Check if parameter counts match
        if (numParams != parameters.length) {
            return true;
        }

        // Check if parameters match in order and storage
        return IntStream.range(0, numParams).anyMatch(i -> {
            final var param = localSymbolMap.getParamSymbol(i);
            
            // Check parameter index
            if (param.getCategoryIndex() != i) {
                return true;
            }
            
            // Check parameter storage (don't use equals for DynamicVariableStorage support)
            return param.getStorage().compareTo(parameters[i].getVariableStorage()) != 0;
        });
    }
}
