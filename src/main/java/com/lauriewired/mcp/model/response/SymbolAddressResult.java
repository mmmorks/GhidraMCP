package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

public record SymbolAddressResult(String symbol, String address) implements Displayable {
    @Override
    public String toDisplayText() {
        return "Symbol '" + symbol + "' found at address: " + address;
    }
}
