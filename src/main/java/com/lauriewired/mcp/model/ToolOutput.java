package com.lauriewired.mcp.model;

/**
 * Sealed interface for typed MCP tool outputs.
 * Each subtype defines its own structured JSON shape.
 */
public sealed interface ToolOutput permits TextOutput, ListOutput, StatusOutput, JsonOutput {

    /** Return the structured JSON representation of this output. */
    String toStructuredJson();

    /**
     * Return the JSON Schema for the given ToolOutput subtype.
     * Used by /mcp/tools to emit outputSchema per tool.
     */
    static String schemaFor(Class<? extends ToolOutput> type) {
        if (type == TextOutput.class) {
            return "{\"type\": \"object\", \"properties\": {\"text\": {\"type\": \"string\"}}, \"required\": [\"text\"]}";
        } else if (type == ListOutput.class) {
            return "{\"type\": \"object\", \"properties\": {"
                + "\"items\": {\"type\": \"array\", \"items\": {\"type\": \"object\"}}, "
                + "\"totalItems\": {\"type\": \"integer\"}, "
                + "\"offset\": {\"type\": \"integer\"}, "
                + "\"limit\": {\"type\": \"integer\"}, "
                + "\"hasMore\": {\"type\": \"boolean\"}"
                + "}, \"required\": [\"items\", \"totalItems\", \"hasMore\"]}";
        } else if (type == StatusOutput.class) {
            return "{\"type\": \"object\", \"properties\": {"
                + "\"success\": {\"type\": \"boolean\"}, "
                + "\"message\": {\"type\": \"string\"}"
                + "}, \"required\": [\"success\", \"message\"]}";
        } else if (type == JsonOutput.class) {
            return "{\"type\": \"object\"}";
        }
        return "{\"type\": \"object\"}";
    }
}
