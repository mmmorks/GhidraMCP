package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record DataFlowResult(
    String function,
    Variable variable,
    List<Reference> references
) implements Displayable {
    public record Variable(String name, String type, String storage) {}

    public record Reference(String address, String kind, String operation, String instruction) {}

    @Override
    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("Data Flow Analysis for variable '").append(variable.name())
          .append("' in function ").append(function).append("\n\n");

        sb.append("Variable information:\n");
        sb.append("  Name: ").append(variable.name()).append("\n");
        sb.append("  Type: ").append(variable.type()).append("\n");
        sb.append("  Storage: ").append(variable.storage() != null ? variable.storage() : "No storage information available").append("\n\n");

        sb.append("Variable definitions and uses:\n");
        for (Reference ref : references) {
            sb.append("  ").append(ref.address()).append(": ")
              .append(ref.kind()).append(": ").append(ref.operation())
              .append(" - ").append(ref.instruction()).append("\n");
        }

        return sb.toString();
    }
}
