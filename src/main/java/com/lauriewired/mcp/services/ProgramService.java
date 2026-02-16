package com.lauriewired.mcp.services;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.ProgramInfoResult;

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

    @McpTool(outputType = JsonOutput.class, responseType = ProgramInfoResult.class, description = """
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

        return new JsonOutput(new ProgramInfoResult(
                program.getName(),
                program.getExecutableFormat(),
                program.getLanguage().getProcessor().toString(),
                program.getLanguageID().toString(),
                program.getLanguage().getLanguageDescription().getEndian().toString(),
                program.getLanguage().getLanguageDescription().getSize(),
                program.getCompilerSpec().getCompilerSpecID().toString(),
                program.getImageBase().toString(),
                program.getMinAddress().toString(),
                program.getMaxAddress().toString(),
                entryPoint,
                program.getFunctionManager().getFunctionCount(),
                program.getSymbolTable().getNumSymbols()));
    }
}
