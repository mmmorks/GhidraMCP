package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record CallGraphResult(
    String function,
    String entryPoint,
    int depth,
    String direction,
    List<CallGraphNode> callers,
    List<CallGraphNode> callees
) implements Displayable {
    public record CallGraphNode(
        String name,
        String address,
        List<CallGraphNode> callers,
        List<CallGraphNode> callees
    ) {}

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Call Graph for ").append(function)
          .append(" at ").append(entryPoint)
          .append(" (direction: ").append(direction)
          .append(", depth: ").append(depth).append(")\n\n");

        if (callers != null && !callers.isEmpty()) {
            sb.append("CALLERS (functions that call ").append(function).append("):\n");
            for (final CallGraphNode node : callers) {
                appendCallGraphNode(sb, node, 0, true);
            }
            sb.append("\n");
        }

        if (callees != null && !callees.isEmpty()) {
            sb.append("CALLEES (functions called by ").append(function).append("):\n");
            for (final CallGraphNode node : callees) {
                appendCallGraphNode(sb, node, 0, false);
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    private static void appendCallGraphNode(final StringBuilder sb, final CallGraphNode node, final int depth, final boolean isCallers) {
        final String indent = "  ".repeat(depth);
        sb.append(indent).append("- ").append(node.name())
          .append(" at ").append(node.address()).append("\n");

        final List<CallGraphNode> children = isCallers ? node.callers() : node.callees();
        if (children != null) {
            for (final CallGraphNode child : children) {
                appendCallGraphNode(sb, child, depth + 1, isCallers);
            }
        }
    }
}
