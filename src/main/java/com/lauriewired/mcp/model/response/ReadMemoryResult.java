package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record ReadMemoryResult(
    String address,
    int size,
    String format,
    List<MemoryRow> rows
) implements Displayable {
    public ReadMemoryResult {
        rows = List.copyOf(rows);
    }

    /**
     * A row of memory bytes starting at a given address.
     * @param address  row start address
     * @param bytes    space-separated byte values formatted according to the requested format
     * @param ascii    printable ASCII representation (null for ascii/binary formats)
     */
    public record MemoryRow(String address, String bytes, String ascii) {}

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(String.format("Memory at %s (%d bytes, %s):\n", address, size, format));
        for (final MemoryRow row : rows) {
            sb.append(row.address()).append(": ");
            sb.append(row.bytes());
            if (row.ascii() != null) {
                // Pad to align ASCII column
                sb.append("  | ").append(row.ascii());
            }
            sb.append("\n");
        }
        return sb.toString();
    }
}
