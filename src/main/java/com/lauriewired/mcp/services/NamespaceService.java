package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.List;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.SymbolAddressResult;
import com.lauriewired.mcp.model.response.SymbolItem;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

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
    public NamespaceService(final ProgramService programService) {
        this.programService = programService;
    }

    @McpTool(description = """
        List data labels (non-function symbols) in the program with pagination.

        Shows named locations such as global variables, data labels, and code labels — excludes
        function entry points (use list_functions for those).

        Returns: Labels with addresses

        Example: list_labels(0, 5) -> ['gVar1 @ 00410010', 'DAT_00410020 @ 00410020', ...] """,
        outputType = ListOutput.class, responseType = SymbolItem.class)
    public ToolOutput listLabels(
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") final int offset,
            @Param(value = "Maximum labels to return", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        final List<SymbolItem> items = new ArrayList<>();
        for (final Symbol symbol : program.getSymbolTable().getAllSymbols(false)) {
            if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                items.add(new SymbolItem(symbol.getName(), symbol.getAddress().toString()));
            }
        }
        return ListOutput.paginate(items, offset, limit);
    }

    @McpTool(outputType = JsonOutput.class, responseType = SymbolAddressResult.class, description = """
        Get the memory address of a named symbol in the program.

        Looks up symbols (functions, variables, labels) by name in the symbol table.

        Returns: Memory address in Ghidra's format or error message

        Note: For functions, returns entry point; for data, returns storage location.

        Example: get_symbol_address("main") -> "00401000" """)
    public ToolOutput getSymbolAddress(
            @Param("Symbol name (case-sensitive, exact match required)") final String symbolName) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (symbolName == null || symbolName.isEmpty()) return StatusOutput.error("Symbol name is required");

        final SymbolTable symbolTable = program.getSymbolTable();
        final SymbolIterator symbolIterator = symbolTable.getSymbols(symbolName);

        if (symbolIterator.hasNext()) {
            final Symbol symbol = symbolIterator.next();
            return new JsonOutput(new SymbolAddressResult(symbolName, symbol.getAddress().toString()));
        } else {
            return StatusOutput.error("Symbol not found");
        }
    }
}
