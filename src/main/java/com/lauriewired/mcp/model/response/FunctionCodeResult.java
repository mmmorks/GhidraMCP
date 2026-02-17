package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record FunctionCodeResult(
    String function,
    String format,
    List<CodeLine> lines
) implements Displayable {
    public FunctionCodeResult {
        lines = List.copyOf(lines);
    }

    /**
     * A single line of code output.
     * @param address  memory address associated with this line (null if none)
     * @param code     the instruction, decompiled code, or pcode text
     * @param comment  end-of-line comment (assembly only, null otherwise)
     */
    public record CodeLine(String address, String code, String comment) {}

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        for (final CodeLine line : lines) {
            if (line.address() != null) {
                sb.append(line.address()).append(": ");
            }
            sb.append(line.code());
            if (line.comment() != null) {
                sb.append(" ; ").append(line.comment());
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
