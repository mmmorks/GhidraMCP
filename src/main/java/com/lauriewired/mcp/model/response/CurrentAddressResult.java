package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

public record CurrentAddressResult(String address) implements Displayable {
    @Override
    public String toDisplayText() {
        return address;
    }
}
