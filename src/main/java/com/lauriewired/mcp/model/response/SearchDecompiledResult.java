package com.lauriewired.mcp.model.response;

import java.util.List;

public record SearchDecompiledResult(String query, int matchCount, List<DecompiledMatch> matches) {
    public record DecompiledMatch(
        String function,
        String address,
        String matchLine,
        List<String> context
    ) {}
}
