package com.lauriewired.mcp.model.response;

import java.util.List;

public record SearchMemoryResult(String query, int matchCount, List<MemoryMatch> matches) {
    public record MemoryMatch(String address, String block, String label, String context) {}
}
