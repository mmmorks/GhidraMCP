package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record SearchDecompiledResult(String query, int matchCount, List<DecompiledMatch> matches) implements Displayable {
    public SearchDecompiledResult {
        matches = List.copyOf(matches);
    }

    public record DecompiledMatch(
        String function,
        String address,
        String matchLine,
        List<String> context
    ) {
        public DecompiledMatch {
            context = List.copyOf(context);
        }
    }

    @Override
    public String toDisplayText() {
        if (matches.isEmpty()) {
            return "No matches found for pattern: " + query;
        }

        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < matches.size(); i++) {
            if (i > 0) sb.append("\n");
            final DecompiledMatch match = matches.get(i);
            sb.append(String.format("Function: %s at %s\n", match.function(), match.address()));
            sb.append("----------------------------------------\n");

            for (final String line : match.context()) {
                sb.append(line).append("\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }
}
