package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

/**
 * Flat memory read result — all requested bytes in a single record.
 * @param address  start address of the read
 * @param size     number of bytes read
 * @param format   output format (hex, decimal, binary, ascii)
 * @param bytes    space-separated byte values formatted per the requested format
 * @param ascii    printable ASCII representation (null for binary/ascii formats)
 * @param comments comments found within the address range (empty if none)
 */
public record ReadMemoryResult(
    String address,
    int size,
    String format,
    String bytes,
    String ascii,
    List<AddressComment> comments
) implements Displayable {

    public record AddressComment(String address, String type, String text) {}

    public ReadMemoryResult {
        comments = (comments != null && !comments.isEmpty()) ? List.copyOf(comments) : null;
    }

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(String.format("Memory at %s (%d bytes, %s):\n", address, size, format));
        sb.append(bytes);
        if (ascii != null) {
            sb.append("  | ").append(ascii);
        }
        if (comments != null && !comments.isEmpty()) {
            sb.append("\nComments:\n");
            for (final AddressComment c : comments) {
                sb.append(String.format("  %s [%s]: %s\n", c.address(), c.type(), c.text()));
            }
        }
        return sb.toString();
    }
}
