package com.lauriewired.mcp.model.response;

public record FunctionByAddressResult(
    String name,
    String signature,
    String entryPoint,
    String bodyStart,
    String bodyEnd
) {}
