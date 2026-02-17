package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

/**
 * Flat memory read result — all requested bytes in a single record.
 * @param address  start address of the read
 * @param size     number of bytes read
 * @param format   output format (hex, decimal, binary, ascii)
 * @param bytes    space-separated byte values formatted per the requested format
 * @param ascii    printable ASCII representation (null for binary/ascii formats)
 */
public record ReadMemoryResult(
    String address,
    int size,
    String format,
    String bytes,
    String ascii
) implements Displayable {

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(String.format("Memory at %s (%d bytes, %s):\n", address, size, format));
        sb.append(bytes);
        if (ascii != null) {
            sb.append("  | ").append(ascii);
        }
        return sb.toString();
    }
}
