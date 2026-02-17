package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record ControlFlowResult(
    String function,
    String entryPoint,
    List<Block> blocks
) implements Displayable {
    public record Block(
        String address,
        Range range,
        List<Successor> successors,
        List<Instruction> instructions
    ) {}

    public record Range(String start, String end) {}

    public record Successor(String type, String target) {}

    public record Instruction(String address, String text) {}

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
            for (final Instruction instr : block.instructions()) {
                sb.append("    ").append(instr.address()).append(": ")
                  .append(instr.text()).append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }
}
