package com.lauriewired.mcp.model.response;

import java.util.Map;

import com.lauriewired.mcp.model.Displayable;

public record SetVariableTypesResult(String status, String function, Map<String, String> applied, int count) implements Displayable {
    public SetVariableTypesResult {
        applied = Map.copyOf(applied);
    }
    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(status).append(" in ").append(function).append("\n");
        for (final var entry : applied.entrySet()) {
            sb.append("  ").append(entry.getKey()).append(" -> ").append(entry.getValue()).append("\n");
        }
        sb.append("Count: ").append(count);
        return sb.toString();
    }
}
