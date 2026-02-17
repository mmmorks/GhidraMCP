package com.lauriewired.mcp.model.response;

import java.util.Map;

import com.lauriewired.mcp.model.Displayable;

public record SetVariableTypesResult(String status, String function, Map<String, String> applied, int count) implements Displayable {
    @Override
    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append(status).append(" in ").append(function).append("\n");
        for (var entry : applied.entrySet()) {
            sb.append("  ").append(entry.getKey()).append(" -> ").append(entry.getValue()).append("\n");
        }
        sb.append("Count: ").append(count);
        return sb.toString();
    }
}
