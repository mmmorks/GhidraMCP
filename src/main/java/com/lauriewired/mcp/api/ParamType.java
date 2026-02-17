package com.lauriewired.mcp.api;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.LinkedHashMap;
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

    ParamType(final String jsonSchemaType) {
        this.jsonSchemaType = jsonSchemaType;
    }

    /**
     * Infer ParamType from a Java reflection Type.
     */
    public static ParamType inferFrom(final Type javaType) {
        if (javaType == String.class) return STRING;
        if (javaType == int.class || javaType == Integer.class) return INTEGER;
        if (javaType == long.class || javaType == Long.class) return LONG;
        if (javaType == boolean.class || javaType == Boolean.class) return BOOLEAN;

        if (javaType instanceof ParameterizedType pt) {
            final Type raw = pt.getRawType();
            final Type[] args = pt.getActualTypeArguments();

            if (raw == Map.class && args.length == 2) {
                if (args[1] == Long.class) return LONG_MAP;
                return STRING_MAP;
            }
            if (raw == List.class && args.length == 1
                    && args[0] instanceof Class<?> c && c.isArray() && c.getComponentType() == String.class) {
                return STRING_PAIR_LIST;
            }
        }

        // Fallback
        return STRING;
    }

    /**
     * Build a JSON Schema Map for this parameter type (used by Jackson serialization in ToolDef).
     */
    public Map<String, Object> toJsonSchemaMap(final String description, boolean required, final String defaultValue) {
        final Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", jsonSchemaType);

        if (description != null && !description.isEmpty()) {
            schema.put("description", description);
        }

        switch (this) {
            case STRING_MAP:
                schema.put("additionalProperties", Map.of("type", "string"));
                break;
            case LONG_MAP:
                schema.put("additionalProperties", Map.of("type", "integer"));
                break;
            case STRING_PAIR_LIST:
                schema.put("items", Map.of("type", "array", "items", Map.of("type", "string")));
                break;
            default:
                break;
        }

        if (defaultValue != null && !defaultValue.equals(Param.REQUIRED)) {
            switch (this) {
                case INTEGER, LONG -> {
                    try { schema.put("default", Long.parseLong(defaultValue)); }
                    catch (NumberFormatException e) { schema.put("default", defaultValue); }
                }
                case BOOLEAN -> schema.put("default", Boolean.parseBoolean(defaultValue));
                default -> schema.put("default", defaultValue);
            }
        }

        return schema;
    }

    /**
     * Parse a raw string value (from GET query or POST body) into the appropriate typed value.
     */
    public Object parseFromString(final String raw, final Object defaultValue) {
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

}
