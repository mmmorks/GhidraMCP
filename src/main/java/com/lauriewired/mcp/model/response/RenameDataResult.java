package com.lauriewired.mcp.model.response;

import java.util.Map;

import com.lauriewired.mcp.model.Displayable;

public record RenameDataResult(String status, Map<String, String> renamed, int count) implements Displayable {
    public RenameDataResult {
        renamed = Map.copyOf(renamed);
    }
    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(status).append("\n");
        for (final var entry : renamed.entrySet()) {
            sb.append("  ").append(entry.getKey()).append(" -> ").append(entry.getValue()).append("\n");
        }
        sb.append("Count: ").append(count);
        return sb.toString();
    }
}
