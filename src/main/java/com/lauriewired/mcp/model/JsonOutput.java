package com.lauriewired.mcp.model;

/**
 * Output for tools that return already-structured JSON (e.g., VariableService methods).
 */
public record JsonOutput(String rawJson) implements ToolOutput {

    @Override
    public String toStructuredJson() {
        return rawJson;
    }

    @Override
    public String toDisplayText() {
        return rawJson;
    }
}
