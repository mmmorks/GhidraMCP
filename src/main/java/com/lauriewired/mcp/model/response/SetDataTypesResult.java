package com.lauriewired.mcp.model.response;

import java.util.Map;

import com.lauriewired.mcp.model.Displayable;

public record SetDataTypesResult(String status, Map<String, String> applied, int count) implements Displayable {
    public SetDataTypesResult {
        applied = Map.copyOf(applied);
    }
    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(status).append("\n");
        for (final var entry : applied.entrySet()) {
            sb.append("  ").append(entry.getKey()).append(" -> ").append(entry.getValue()).append("\n");
        }
        sb.append("Count: ").append(count);
        return sb.toString();
    }
}
