package com.lauriewired.mcp.services;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;

/**
 * Service for accessing the current program in Ghidra
 */
public class ProgramService {
    private final PluginTool tool;

    /**
     * Creates a new ProgramService
     * 
     * @param tool the plugin tool from Ghidra
     */
    public ProgramService(PluginTool tool) {
        this.tool = tool;
    }

    /**
     * Gets the currently active program in Ghidra
     * 
     * @return the current program or null if none is loaded
     */
    public Program getCurrentProgram() {
        if (tool == null) {
            return null;
        }

        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    /**
     * Get metadata about the currently loaded program.
     *
     * @return formatted program information string
     */
    public String getProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder sb = new StringBuilder();
        sb.append("Program: ").append(program.getName()).append("\n");
        sb.append("Format: ").append(program.getExecutableFormat()).append("\n");
        sb.append("Processor: ").append(program.getLanguage().getProcessor().toString()).append("\n");
        sb.append("Architecture: ").append(program.getLanguageID()).append("\n");
        sb.append("Endian: ").append(program.getLanguage().getLanguageDescription().getEndian().toString()).append("\n");
        sb.append("Address Size: ").append(program.getLanguage().getLanguageDescription().getSize()).append("\n");
        sb.append("Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        sb.append("Image Base: ").append(program.getImageBase()).append("\n");
        sb.append("Address Range: ").append(program.getMinAddress()).append(" - ").append(program.getMaxAddress()).append("\n");

        // Entry point
        AddressIterator entryPoints = program.getSymbolTable().getExternalEntryPointIterator();
        if (entryPoints.hasNext()) {
            sb.append("Entry Point: ").append(entryPoints.next()).append("\n");
        }

        sb.append("Functions: ").append(program.getFunctionManager().getFunctionCount()).append("\n");
        sb.append("Symbols: ").append(program.getSymbolTable().getNumSymbols()).append("\n");

        return sb.toString();
    }
}
