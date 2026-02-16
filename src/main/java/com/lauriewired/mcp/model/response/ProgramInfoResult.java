package com.lauriewired.mcp.model.response;

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
) {}
