package com.lauriewired.mcp.services;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.JsonBuilder;

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

    @McpTool(outputType = JsonOutput.class, description = """
        Get metadata about the currently loaded binary.

        Returns architecture, endianness, file format, base address, entry point,
        and counts of functions/symbols. This is typically the first tool to call
        when starting analysis of a new binary.

        Returns: Program metadata including processor, format, addresses, and counts

        Example: get_program_info() -> "Program: firmware.bin\\nFormat: ELF\\nProcessor: ARM..." """)
    public ToolOutput getProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        // Entry point
        AddressIterator entryPoints = program.getSymbolTable().getExternalEntryPointIterator();
        String entryPoint = entryPoints.hasNext() ? entryPoints.next().toString() : null;

        String json = JsonBuilder.object()
                .put("name", program.getName())
                .put("format", program.getExecutableFormat())
                .put("processor", program.getLanguage().getProcessor().toString())
                .put("architecture", program.getLanguageID().toString())
                .put("endian", program.getLanguage().getLanguageDescription().getEndian().toString())
                .put("addressSize", program.getLanguage().getLanguageDescription().getSize())
                .put("compiler", program.getCompilerSpec().getCompilerSpecID().toString())
                .put("imageBase", program.getImageBase().toString())
                .put("minAddress", program.getMinAddress().toString())
                .put("maxAddress", program.getMaxAddress().toString())
                .putIfNotNull("entryPoint", entryPoint)
                .put("functionCount", program.getFunctionManager().getFunctionCount())
                .put("symbolCount", program.getSymbolTable().getNumSymbols())
                .build();

        return new JsonOutput(json);
    }
}
