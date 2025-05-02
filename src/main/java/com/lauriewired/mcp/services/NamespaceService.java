package com.lauriewired.mcp.services;

import com.lauriewired.mcp.utils.HttpUtils;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
     * List all namespace/class names in the program with pagination
     *
     * @param offset starting index
     * @param limit maximum number of names to return
     * @return list of class names
     */
    public String getAllClassNames(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return HttpUtils.paginateList(sorted, offset, limit);
    }

    /**
     * List all non-global namespaces in the program
     *
     * @param offset starting index
     * @param limit maximum number of namespaces to return
     * @return list of namespace names
     */
    public String listNamespaces(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return HttpUtils.paginateList(sorted, offset, limit);
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
     * List imported symbols in the program
     *
     * @param offset starting index
     * @param limit maximum number of imported symbols to return
     * @return list of imported symbol names and addresses
     */
    public String listImports(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }

    /**
     * List exported functions/symbols
     *
     * @param offset starting index
     * @param limit maximum number of exported symbols to return
     * @return list of exported symbol names and addresses
     */
    public String listExports(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
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
