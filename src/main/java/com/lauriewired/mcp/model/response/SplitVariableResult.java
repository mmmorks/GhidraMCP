package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record SplitVariableResult(
    String status,
    String originalVariable,
    String newVariable,
    String splitAddress,
    List<VarInfo> variables,
    String decompiled
) implements Displayable {
    public SplitVariableResult {
        variables = variables != null ? List.copyOf(variables) : null;
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

        if (decompiled != null) {
            sb.append("\nDecompiled:\n").append(decompiled);
        }
        return sb.toString();
    }
}
