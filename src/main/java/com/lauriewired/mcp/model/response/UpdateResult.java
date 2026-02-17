package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record UpdateResult(String name, List<String> results, Summary summary) implements Displayable {
    public record Summary(int succeeded, int failed) {}

    @Override
    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("Updated '").append(name).append("':\n");
        for (String r : results) {
            sb.append(r).append("\n");
        }
        sb.append("Summary: ").append(summary.succeeded()).append(" succeeded, ")
          .append(summary.failed()).append(" failed");
        return sb.toString();
    }
}
