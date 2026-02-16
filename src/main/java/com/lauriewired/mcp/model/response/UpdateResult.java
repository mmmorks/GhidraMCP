package com.lauriewired.mcp.model.response;

import java.util.List;

public record UpdateResult(String name, List<String> results, Summary summary) {
    public record Summary(int succeeded, int failed) {}
}
