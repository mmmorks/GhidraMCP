package com.lauriewired.mcp.model;

import com.lauriewired.mcp.utils.HttpUtils;

/**
 * Output for mutation operations that return success/failure status.
 */
public record StatusOutput(boolean success, String message) implements ToolOutput {

    /** Convenience factory for a successful result. */
    public static StatusOutput ok(String message) {
        return new StatusOutput(true, message);
    }

    /** Convenience factory for an error result. */
    public static StatusOutput error(String message) {
        return new StatusOutput(false, message);
    }

    @Override
    public String toStructuredJson() {
        return "{\"success\": " + success + ", \"message\": \"" + HttpUtils.escapeJson(message) + "\"}";
    }

    @Override
    public String toDisplayText() {
        return message;
    }
}
