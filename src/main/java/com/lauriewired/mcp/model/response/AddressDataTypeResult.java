package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

public record AddressDataTypeResult(
    String address,
    String category,
    String mnemonic,
    String operands,
    String dataType,
    Integer length,
    String value,
    String label
) implements Displayable {
    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Data type at ").append(address).append(":\n");
        sb.append("  Type: ").append(category).append("\n");
        if (mnemonic != null) {
            sb.append("  Mnemonic: ").append(mnemonic).append("\n");
        }
        if (operands != null) {
            sb.append("  Operands: ").append(operands).append("\n");
        }
        if (dataType != null) {
            sb.append("  Data Type: ").append(dataType).append("\n");
        }
        if (length != null) {
            sb.append("  Length: ").append(length).append(" bytes\n");
        }
        if (value != null) {
            sb.append("  Value: ").append(value).append("\n");
        }
        if (label != null) {
            sb.append("  Label: ").append(label);
        }
        return sb.toString();
    }
}
