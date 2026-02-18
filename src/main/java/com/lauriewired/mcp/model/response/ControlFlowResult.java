package com.lauriewired.mcp.model.response;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.lauriewired.mcp.model.Displayable;

public record ControlFlowResult(
    String function,
    String entryPoint,
    List<Block> blocks
) implements Displayable {
    public ControlFlowResult {
        blocks = List.copyOf(blocks);
    }

    public record Block(
        String address,
        Range range,
        List<Successor> successors,
        List<Map<String, String>> instructions
    ) {
        public Block {
            successors = List.copyOf(successors);
            instructions = List.copyOf(instructions);
        }
    }

    public record Range(String start, String end) {}

    public record Successor(String type, String target) {}

    public static Map<String, String> instruction(final String address, final String text) {
        final Map<String, String> entry = new LinkedHashMap<>(1);
        entry.put(address != null ? address : "", text);
        return entry;
    }

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Control Flow Analysis for function: ").append(function)
          .append(" at ").append(entryPoint).append("\n\n");

        for (final Block block : blocks) {
            sb.append("Block at ").append(block.address())
              .append(" (").append(block.range().start()).append(" - ")
              .append(block.range().end()).append(")\n");

            if (block.successors().isEmpty()) {
                sb.append("  - Terminal block (no successors)\n");
            } else {
                for (final Successor succ : block.successors()) {
                    sb.append("  - ").append(succ.type()).append(" to ")
                      .append(succ.target()).append("\n");
                }
            }

            sb.append("  Instructions:\n");
            for (final Map<String, String> instr : block.instructions()) {
                final var e = instr.entrySet().iterator().next();
                sb.append("    ").append(e.getKey()).append(": ")
                  .append(e.getValue()).append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }
}
