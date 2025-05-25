package com.lauriewired.mcp.services;

import ghidra.framework.plugintool.PluginTool;

/**
 * Wrapper interface for PluginTool to enable mocking in tests.
 * This interface extracts the methods we need to mock from PluginTool.
 */
public interface MockablePluginTool {
    /**
     * Gets a service from the tool.
     * 
     * @param <T> the service type
     * @param serviceClass the service class
     * @return the service instance or null if not available
     */
    <T> T getService(Class<T> serviceClass);
    
    /**
     * Gets the actual PluginTool instance.
     * 
     * @return the wrapped PluginTool
     */
    PluginTool getTool();
}

/**
 * Default implementation that delegates to a real PluginTool.
 */
class PluginToolWrapper implements MockablePluginTool {
    private final PluginTool tool;
    
    public PluginToolWrapper(PluginTool tool) {
        this.tool = tool;
    }
    
    @Override
    public <T> T getService(Class<T> serviceClass) {
        return tool != null ? tool.getService(serviceClass) : null;
    }
    
    @Override
    public PluginTool getTool() {
        return tool;
    }
}