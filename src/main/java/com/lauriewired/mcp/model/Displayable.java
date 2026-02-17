package com.lauriewired.mcp.model;

/**
 * Interface for response records that can produce human-readable display text.
 * Used by JsonOutput to provide a text representation distinct from the structured JSON.
 */
public interface Displayable {
    String toDisplayText();
}
