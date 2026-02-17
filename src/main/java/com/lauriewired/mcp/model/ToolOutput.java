package com.lauriewired.mcp.model;

/**
 * Sealed interface for typed MCP tool outputs.
 * Each subtype defines its own structured JSON shape.
 */
public sealed interface ToolOutput permits ListOutput, StatusOutput, JsonOutput {

    /** Return the structured JSON representation of this output. */
    String toStructuredJson();

    /** Return the human-readable display text for MCP content (backward-compatible with older clients). */
    String toDisplayText();
}
