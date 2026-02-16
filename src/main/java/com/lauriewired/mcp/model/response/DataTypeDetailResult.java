package com.lauriewired.mcp.model.response;

import java.util.List;

public record DataTypeDetailResult(
    String kind,
    String name,
    int size,
    String description,
    List<Field> fields,
    List<Value> values
) {
    public record Field(int offset, String name, String type, int size, String comment) {}

    public record Value(String name, long value) {}
}
