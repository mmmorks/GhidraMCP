package com.lauriewired.mcp.model.response;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.lauriewired.mcp.model.Displayable;

public record FunctionCodeResult(
    String function,
    String prototype,
    String format,
    List<RegisterAssumption> registerAssumptions,
    List<Map<String, String>> lines
) implements Displayable {
    public FunctionCodeResult {
        registerAssumptions = registerAssumptions != null ? List.copyOf(registerAssumptions) : null;
        lines = List.copyOf(lines);
    }

    public record RegisterAssumption(String name, String value) {}

    public static Map<String, String> line(final String address, final String code) {
        final Map<String, String> entry = new LinkedHashMap<>(1);
        entry.put(address != null ? address : "", code);
        return entry;
    }

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        if (registerAssumptions != null && !registerAssumptions.isEmpty()) {
            sb.append("Register Assumptions:\n");
            for (final RegisterAssumption assumption : registerAssumptions) {
                sb.append("  assume ").append(assumption.name())
                  .append(" = ").append(assumption.value()).append('\n');
            }
            sb.append('\n');
        }
        for (final Map<String, String> entry : lines) {
            final var e = entry.entrySet().iterator().next();
            final String addr = e.getKey();
            if (!addr.isEmpty()) {
                sb.append(addr).append(": ");
            }
            sb.append(e.getValue());
            sb.append('\n');
        }
        return sb.toString();
    }
}
