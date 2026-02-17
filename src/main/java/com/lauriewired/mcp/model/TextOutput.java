package com.lauriewired.mcp.model;

import com.lauriewired.mcp.utils.Json;

/**
 * Output for tools that return free-form text (code, analysis, info, hex dumps).
 */
public record TextOutput(String text) implements ToolOutput {

    @Override
    public String toStructuredJson() {
        return Json.serialize(this);
    }

    @Override
    public String toDisplayText() {
        return text;
    }
}
