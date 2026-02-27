package com.lauriewired.mcp.model.response;

public record MemorySegmentItem(String name, String start, String end, long size, String permissions,
                                String blockType, boolean initialized, boolean isVolatile,
                                String byteSource) {}
