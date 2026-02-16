package com.lauriewired.mcp.model;

import com.lauriewired.mcp.utils.HttpUtils;

/**
 * Output for tools that return free-form text (code, analysis, info, hex dumps).
 */
public record TextOutput(String text) implements ToolOutput {

    @Override
    public String toStructuredJson() {
        return "{\"text\": \"" + HttpUtils.escapeJson(text) + "\"}";
    }

}
