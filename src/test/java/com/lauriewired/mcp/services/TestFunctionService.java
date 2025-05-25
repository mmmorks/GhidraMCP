package com.lauriewired.mcp.services;

import ghidra.framework.plugintool.PluginTool;

/**
 * Test-friendly version of FunctionService that can work with TestProgramService
 */
public class TestFunctionService extends FunctionService {
    
    /**
     * Creates a TestFunctionService with a MockablePluginTool
     * 
     * @param mockableTool the mockable plugin tool
     * @param programService the program service
     */
    public TestFunctionService(MockablePluginTool mockableTool, ProgramService programService) {
        super(mockableTool != null ? mockableTool.getTool() : null, programService);
    }
    
    /**
     * Creates a TestFunctionService with a regular PluginTool
     * 
     * @param tool the plugin tool
     * @param programService the program service
     */
    public TestFunctionService(PluginTool tool, ProgramService programService) {
        super(tool, programService);
    }
}