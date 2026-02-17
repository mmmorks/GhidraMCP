package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

public record ProgramInfoResult(
    String name,
    String format,
    String processor,
    String architecture,
    String endian,
    int addressSize,
    String compiler,
    String imageBase,
    String minAddress,
    String maxAddress,
    String entryPoint,
    int functionCount,
    int symbolCount
) implements Displayable {
    @Override
    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();
        sb.append("Program: ").append(name).append("\n");
        sb.append("Format: ").append(format).append("\n");
        sb.append("Processor: ").append(processor).append("\n");
        sb.append("Architecture: ").append(architecture).append("\n");
        sb.append("Endian: ").append(endian).append("\n");
        sb.append("Address Size: ").append(addressSize).append("\n");
        sb.append("Compiler: ").append(compiler).append("\n");
        sb.append("Image Base: ").append(imageBase).append("\n");
        sb.append("Address Range: ").append(minAddress).append(" - ").append(maxAddress).append("\n");
        if (entryPoint != null) {
            sb.append("Entry Point: ").append(entryPoint).append("\n");
        }
        sb.append("Functions: ").append(functionCount).append("\n");
        sb.append("Symbols: ").append(symbolCount);
        return sb.toString();
    }
}
