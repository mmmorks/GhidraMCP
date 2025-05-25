package com.lauriewired.mcp.services;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Test-friendly version of ProgramService that can work with mockable interfaces
 */
public class TestProgramService extends ProgramService {
    private final MockablePluginTool mockableTool;
    
    /**
     * Creates a TestProgramService with a MockablePluginTool
     * 
     * @param mockableTool the mockable plugin tool
     */
    public TestProgramService(MockablePluginTool mockableTool) {
        super(mockableTool != null ? mockableTool.getTool() : null);
        this.mockableTool = mockableTool;
    }
    
    /**
     * Creates a TestProgramService with a regular PluginTool
     * 
     * @param tool the plugin tool
     */
    public TestProgramService(PluginTool tool) {
        super(tool);
        this.mockableTool = tool != null ? new PluginToolWrapper(tool) : null;
    }
    
    @Override
    public Program getCurrentProgram() {
        if (mockableTool == null) {
            return null;
        }
        
        ProgramManager pm = mockableTool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }
}