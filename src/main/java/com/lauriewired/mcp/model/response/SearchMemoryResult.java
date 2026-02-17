package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record SearchMemoryResult(String query, int matchCount, List<MemoryMatch> matches) implements Displayable {
    public record MemoryMatch(String address, String block, String label, String context) {}

    @Override
    public String toDisplayText() {
        if (matches.isEmpty()) {
            return "No matches found for query: " + query;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < matches.size(); i++) {
            if (i > 0) sb.append("\n");
            MemoryMatch m = matches.get(i);
            sb.append("Match at: ").append(m.address());
            if (m.block() != null) {
                sb.append(" (").append(m.block()).append(")");
            }
            sb.append("\n");
            if (m.label() != null) {
                sb.append("Label: ").append(m.label()).append("\n");
            }
            if (m.context() != null) {
                sb.append("Context:\n").append(m.context());
            }
        }
        return sb.toString();
    }
}
