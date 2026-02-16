package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.List;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
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

    @McpTool(description = """
        List all symbols (functions, variables, labels, etc.) with pagination.

        Comprehensive listing of all named entities in the program.

        Returns: Symbols with addresses in format "symbol_name -> address"

        Example: list_symbols(0, 5) -> ['main -> 00401000', 'gVar1 -> 00410010', ...] """)
    public String listSymbols(
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") int offset,
            @Param(value = "Maximum symbols to return", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(false)) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }
    
    @McpTool(description = """
        Get the memory address of a named symbol in the program.

        Looks up symbols (functions, variables, labels) by name in the symbol table.

        Returns: Memory address in Ghidra's format or error message

        Note: For functions, returns entry point; for data, returns storage location.

        Example: get_symbol_address("main") -> "00401000" """)
    public String getSymbolAddress(
            @Param("Symbol name (case-sensitive, exact match required)") String symbolName) {
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
