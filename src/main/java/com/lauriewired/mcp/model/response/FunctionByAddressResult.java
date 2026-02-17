package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

public record FunctionByAddressResult(
    String name,
    String signature,
    String entryPoint,
    String bodyStart,
    String bodyEnd
) implements Displayable {
    @Override
    public String toDisplayText() {
        return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
            name, entryPoint, signature, entryPoint, bodyStart, bodyEnd);
    }
}
