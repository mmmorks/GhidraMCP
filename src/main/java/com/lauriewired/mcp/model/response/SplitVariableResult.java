package com.lauriewired.mcp.model.response;

import java.util.List;

public record SplitVariableResult(
    String status,
    String originalVariable,
    String newVariable,
    String splitAddress,
    List<VarInfo> variables,
    String decompiled
) {
    public record VarInfo(String name, String dataType, String storage) {}
}
