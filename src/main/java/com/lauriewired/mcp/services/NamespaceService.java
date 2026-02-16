package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.List;

import com.lauriewired.mcp.utils.HttpUtils;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Service for operations related to namespaces, classes, and symbols
 */
public class NamespaceService {
    private final ProgramService programService;

    /**
     * Creates a new NamespaceService
     *
     * @param programService the program service for accessing the current program
     */
    public NamespaceService(ProgramService programService) {
        this.programService = programService;
    }

    /**
     * List all symbols in the program with pagination
     *
     * @param offset starting index
     * @param limit maximum number of symbols to return
     * @return list of symbol names and addresses
     */
    public String listSymbols(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(false)) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }
    
    /**
     * Get the address of a symbol by name
     *
     * @param symbolName name of the symbol to look up
     * @return symbol address or error message
     */
    public String getSymbolAddress(String symbolName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (symbolName == null || symbolName.isEmpty()) return "Symbol name is required";

        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbolIterator = symbolTable.getSymbols(symbolName);
        
        if (symbolIterator.hasNext()) {
            // Use the first matching symbol's address
            Symbol symbol = symbolIterator.next();
            return "Symbol '" + symbolName + "' found at address: " + symbol.getAddress().toString();
        } else {
            return "Symbol not found";
        }
    }
}
