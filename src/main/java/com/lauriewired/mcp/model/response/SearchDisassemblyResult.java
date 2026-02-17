package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record SearchDisassemblyResult(String query, int matchCount, List<DisasmMatch> matches) implements Displayable {
    public record DisasmMatch(
        String address,
        String function,
        String matchedInstruction,
        List<ContextLine> context
    ) {}

    public record ContextLine(String address, String text, boolean isMatch) {}

    @Override
    public String toDisplayText() {
        if (matches.isEmpty()) {
            return "No matches found for pattern: " + query;
        }

        final StringBuilder sb = new StringBuilder();
        for (final DisasmMatch match : matches) {
            if (match.function() != null) {
                sb.append(String.format("Location: %s (in function %s)\n", match.address(), match.function()));
            } else {
                sb.append(String.format("Location: %s\n", match.address()));
            }
            sb.append("----------------------------------------\n");

            for (final ContextLine line : match.context()) {
                final String prefix = line.isMatch() ? "\u2192 " : "  ";
                sb.append(prefix).append(line.address()).append(": ").append(line.text()).append("\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }
}
