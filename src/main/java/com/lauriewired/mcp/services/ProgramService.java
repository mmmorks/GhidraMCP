package com.lauriewired.mcp.services;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
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
}
