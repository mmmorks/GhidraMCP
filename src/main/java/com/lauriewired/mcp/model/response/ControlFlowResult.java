package com.lauriewired.mcp.model.response;

import java.util.List;

public record ControlFlowResult(
    String function,
    String entryPoint,
    List<Block> blocks
) {
    public record Block(
        String address,
        Range range,
        List<Successor> successors,
        List<Instruction> instructions
    ) {}

    public record Range(String start, String end) {}

    public record Successor(String type, String target) {}

    public record Instruction(String address, String text) {}
}
