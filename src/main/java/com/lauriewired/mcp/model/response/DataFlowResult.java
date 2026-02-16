package com.lauriewired.mcp.model.response;

import java.util.List;

public record DataFlowResult(
    String function,
    Variable variable,
    List<Reference> references
) {
    public record Variable(String name, String type, String storage) {}

    public record Reference(String address, String kind, String operation, String instruction) {}
}
