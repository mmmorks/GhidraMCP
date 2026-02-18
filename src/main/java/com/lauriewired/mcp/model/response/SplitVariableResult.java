package com.lauriewired.mcp.model.response;

import java.util.List;
import java.util.Map;

import com.lauriewired.mcp.model.Displayable;

public record SplitVariableResult(
    String status,
    String originalVariable,
    String newVariable,
    String splitAddress,
    List<VarInfo> variables,
    List<Map<String, String>> decompiledLines
) implements Displayable {
    public SplitVariableResult {
        variables = variables != null ? List.copyOf(variables) : null;
        decompiledLines = decompiledLines != null ? List.copyOf(decompiledLines) : null;
    }
    public record VarInfo(String name, String dataType, String storage) {}

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(status).append("\n");
        sb.append("  Original: ").append(originalVariable).append("\n");
        sb.append("  New: ").append(newVariable).append("\n");
        if (splitAddress != null) {
            sb.append("  Split address: ").append(splitAddress).append("\n");
        }

        if (variables != null && !variables.isEmpty()) {
            sb.append("\nVariables:\n");
            for (final VarInfo v : variables) {
                sb.append("  ").append(v.name()).append(": ").append(v.dataType());
                if (v.storage() != null) {
                    sb.append(" (").append(v.storage()).append(")");
                }
                sb.append("\n");
            }
        }

        if (decompiledLines != null && !decompiledLines.isEmpty()) {
            sb.append("\nDecompiled:\n");
            for (final Map<String, String> entry : decompiledLines) {
                final var e = entry.entrySet().iterator().next();
                final String addr = e.getKey();
                if (!addr.isEmpty()) {
                    sb.append(addr).append(": ");
                }
                sb.append(e.getValue()).append("\n");
            }
        }
        return sb.toString();
    }
}
