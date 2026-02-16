package com.lauriewired.mcp.model.response;

public record AddressDataTypeResult(
    String address,
    String category,
    String mnemonic,
    String operands,
    String dataType,
    Integer length,
    String value,
    String label
) {}
