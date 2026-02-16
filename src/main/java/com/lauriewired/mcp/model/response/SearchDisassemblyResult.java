package com.lauriewired.mcp.model.response;

import java.util.List;

public record SearchDisassemblyResult(String query, int matchCount, List<DisasmMatch> matches) {
    public record DisasmMatch(
        String address,
        String function,
        String matchedInstruction,
        List<ContextLine> context
    ) {}

    public record ContextLine(String address, String text, boolean isMatch) {}
}
