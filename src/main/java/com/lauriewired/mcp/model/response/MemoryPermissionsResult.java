package com.lauriewired.mcp.model.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.lauriewired.mcp.model.Displayable;

public record MemoryPermissionsResult(
    String block,
    String start,
    String end,
    long size,
    Permissions permissions,
    boolean initialized,
    @JsonProperty("volatile") boolean isVolatile,
    boolean overlay
) implements Displayable {
    public record Permissions(boolean read, boolean write, boolean execute) {}

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Memory permissions at ").append(start).append(":\n");
        sb.append("  Block: ").append(block).append("\n");
        sb.append("  Start: ").append(start).append("\n");
        sb.append("  End: ").append(end).append("\n");
        sb.append(String.format("  Size: 0x%X bytes\n", size));
        sb.append("  Permissions:\n");
        sb.append("    Read: ").append(permissions.read() ? "Yes" : "No").append("\n");
        sb.append("    Write: ").append(permissions.write() ? "Yes" : "No").append("\n");
        sb.append("    Execute: ").append(permissions.execute() ? "Yes" : "No").append("\n");
        sb.append("  Type:\n");
        sb.append("    Initialized: ").append(initialized ? "Yes" : "No").append("\n");
        sb.append("    Volatile: ").append(isVolatile ? "Yes" : "No").append("\n");
        sb.append("    Overlay: ").append(overlay ? "Yes" : "No");
        return sb.toString();
    }
}
