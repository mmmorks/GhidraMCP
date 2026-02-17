package com.lauriewired.mcp.model.response;

import java.util.List;

import com.lauriewired.mcp.model.Displayable;

public record DataTypeDetailResult(
    String kind,
    String name,
    int size,
    String description,
    List<Field> fields,
    List<Value> values
) implements Displayable {
    public record Field(int offset, String name, String type, int size, String comment) {}

    public record Value(String name, long value) {}

    @Override
    public String toDisplayText() {
        StringBuilder sb = new StringBuilder();

        if ("Structure".equals(kind)) {
            sb.append("Structure: ").append(name).append("\n");
            sb.append("Size: ").append(size).append(" bytes\n");
            if (description != null) {
                sb.append("Description: ").append(description).append("\n");
            }
            sb.append("\nFields:\n");
            if (fields == null || fields.isEmpty()) {
                sb.append("  (no fields defined)\n");
            } else {
                for (Field f : fields) {
                    sb.append(String.format("  [%04X] %s: %s (%d bytes)",
                        f.offset(),
                        f.name() != null ? f.name() : "(unnamed)",
                        f.type(),
                        f.size()));
                    if (f.comment() != null) {
                        sb.append(" // ").append(f.comment());
                    }
                    sb.append("\n");
                }
            }
        } else if ("Enum".equals(kind)) {
            sb.append("Enum: ").append(name).append("\n");
            sb.append("Size: ").append(size).append(" bytes\n");
            if (description != null) {
                sb.append("Description: ").append(description).append("\n");
            }
            sb.append("\nValues:\n");
            if (values == null || values.isEmpty()) {
                sb.append("  (no values defined)\n");
            } else {
                for (Value v : values) {
                    sb.append(String.format("  %s = 0x%X (%d)\n", v.name(), v.value(), v.value()));
                }
            }
        } else {
            sb.append("Data Type: ").append(name).append("\n");
            sb.append("Kind: ").append(kind).append("\n");
            sb.append("Size: ").append(size).append(" bytes\n");
            if (description != null) {
                sb.append("Description: ").append(description);
            }
        }

        return sb.toString();
    }
}
