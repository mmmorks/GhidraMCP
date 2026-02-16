package com.lauriewired.mcp.model.response;

import java.util.List;

public record CallGraphResult(
    String function,
    String entryPoint,
    int depth,
    String direction,
    List<CallGraphNode> callers,
    List<CallGraphNode> callees
) {
    public record CallGraphNode(
        String name,
        String address,
        List<CallGraphNode> callers,
        List<CallGraphNode> callees
    ) {}
}
