package com.lauriewired.mcp.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MemoryPermissionsResult(
    String block,
    String start,
    String end,
    long size,
    Permissions permissions,
    boolean initialized,
    @JsonProperty("volatile") boolean isVolatile,
    boolean overlay
) {
    public record Permissions(boolean read, boolean write, boolean execute) {}
}
