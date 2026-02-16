package com.lauriewired.mcp.api;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;

/**
 * Maps Java parameter types to JSON Schema types for MCP tool definitions.
 */
public enum ParamType {
    STRING("string"),
    INTEGER("integer"),
    LONG("integer"),
    BOOLEAN("boolean"),
    STRING_MAP("object"),
    LONG_MAP("object"),
    STRING_PAIR_LIST("array");

    private final String jsonSchemaType;

    ParamType(String jsonSchemaType) {
        this.jsonSchemaType = jsonSchemaType;
    }

    /**
     * Infer ParamType from a Java reflection Type.
     */
    public static ParamType inferFrom(Type javaType) {
        if (javaType == String.class) return STRING;
        if (javaType == int.class || javaType == Integer.class) return INTEGER;
        if (javaType == long.class || javaType == Long.class) return LONG;
        if (javaType == boolean.class || javaType == Boolean.class) return BOOLEAN;

        if (javaType instanceof ParameterizedType pt) {
            Type raw = pt.getRawType();
            Type[] args = pt.getActualTypeArguments();

            if (raw == Map.class && args.length == 2) {
                if (args[1] == Long.class) return LONG_MAP;
                return STRING_MAP;
            }
            if (raw == List.class && args.length == 1) {
                // List<String[]> → STRING_PAIR_LIST
                if (args[0] instanceof Class<?> c && c.isArray() && c.getComponentType() == String.class) {
                    return STRING_PAIR_LIST;
                }
            }
        }

        // Fallback
        return STRING;
    }

    /**
     * Generate a JSON Schema fragment for this parameter type.
     */
    public String toJsonSchemaFragment(String name, String description, boolean required, String defaultValue) {
        StringBuilder sb = new StringBuilder();
        sb.append("\"").append(name).append("\": {");
        sb.append("\"type\": \"").append(jsonSchemaType).append("\"");

        if (description != null && !description.isEmpty()) {
            sb.append(", \"description\": \"").append(escapeJson(description)).append("\"");
        }

        // Add nested type info for maps and arrays
        switch (this) {
            case STRING_MAP:
                sb.append(", \"additionalProperties\": {\"type\": \"string\"}");
                break;
            case LONG_MAP:
                sb.append(", \"additionalProperties\": {\"type\": \"integer\"}");
                break;
            case STRING_PAIR_LIST:
                sb.append(", \"items\": {\"type\": \"array\", \"items\": {\"type\": \"string\"}}");
                break;
            default:
                break;
        }

        if (defaultValue != null && !defaultValue.equals(Param.REQUIRED)) {
            switch (this) {
                case INTEGER:
                case LONG:
                    sb.append(", \"default\": ").append(defaultValue);
                    break;
                case BOOLEAN:
                    sb.append(", \"default\": ").append(defaultValue);
                    break;
                default:
                    sb.append(", \"default\": \"").append(escapeJson(defaultValue)).append("\"");
                    break;
            }
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Parse a raw string value (from GET query or POST body) into the appropriate typed value.
     */
    public Object parseFromString(String raw, Object defaultValue) {
        if (raw == null || raw.isEmpty()) return defaultValue;

        return switch (this) {
            case STRING -> raw;
            case INTEGER -> {
                try {
                    yield Integer.parseInt(raw);
                } catch (NumberFormatException e) {
                    yield defaultValue;
                }
            }
            case LONG -> {
                try {
                    if (raw.startsWith("0x") || raw.startsWith("0X")) {
                        yield Long.parseLong(raw.substring(2), 16);
                    }
                    yield Long.parseLong(raw);
                } catch (NumberFormatException e) {
                    yield defaultValue;
                }
            }
            case BOOLEAN -> Boolean.parseBoolean(raw);
            default -> raw; // Maps and lists are handled separately via JSON body parsing
        };
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
