package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

public record CurrentFunctionResult(String name, String entryPoint, String signature) implements Displayable {
    @Override
    public String toDisplayText() {
        return String.format("Function: %s at %s\nSignature: %s", name, entryPoint, signature);
    }
}
