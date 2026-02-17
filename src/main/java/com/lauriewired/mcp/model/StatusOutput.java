package com.lauriewired.mcp.model;

import com.lauriewired.mcp.utils.Json;

/**
 * Output for mutation operations that return success/failure status.
 */
public record StatusOutput(boolean success, String message) implements ToolOutput {

    /** Convenience factory for a successful result. */
    public static StatusOutput ok(final String message) {
        return new StatusOutput(true, message);
    }

    /** Convenience factory for an error result. */
    public static StatusOutput error(final String message) {
        return new StatusOutput(false, message);
    }

    @Override
    public String toStructuredJson() {
        return Json.serialize(this);
    }

    @Override
    public String toDisplayText() {
        return message;
    }
}
