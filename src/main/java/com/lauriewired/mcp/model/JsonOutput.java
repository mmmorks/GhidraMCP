package com.lauriewired.mcp.model;

import com.lauriewired.mcp.utils.Json;

/**
 * Output for tools that return structured data via record objects.
 * The data object is serialized to JSON via Jackson.
 */
public record JsonOutput(Object data) implements ToolOutput {

    @Override
    public String toStructuredJson() {
        if (data instanceof String s) {
            // Legacy support: if data is already a JSON string, return as-is
            return s;
        }
        return Json.serialize(data);
    }

    @Override
    public String toDisplayText() {
        if (data instanceof Displayable d) {
            return d.toDisplayText();
        }
        return toStructuredJson();
    }
}
