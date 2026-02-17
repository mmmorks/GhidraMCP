package com.lauriewired.mcp.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;

/**
 * Shared ObjectMapper singleton for JSON serialization.
 * Configured with NON_NULL inclusion and snake_case naming to match MCP conventions.
 */
public final class Json {
    private static final PropertyNamingStrategies.SnakeCaseStrategy SNAKE_CASE =
        (PropertyNamingStrategies.SnakeCaseStrategy) PropertyNamingStrategies.SNAKE_CASE;

    private static final ObjectMapper MAPPER = new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .setPropertyNamingStrategy(SNAKE_CASE);

    private Json() {}

    /**
     * Convert a camelCase string to snake_case.
     * Single source of truth for naming conversion across the codebase.
     */
    public static String toSnakeCase(final String camel) {
        return SNAKE_CASE.translate(camel);
    }

    /**
     * Serialize an object to a JSON string.
     *
     * @param value the object to serialize
     * @return JSON string representation
     * @throws RuntimeException if serialization fails
     */
    public static String serialize(final Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON serialization failed", e);
        }
    }

    /**
     * Deserialize a JSON string to the given type.
     *
     * @throws RuntimeException if deserialization fails
     */
    public static <T> T readValue(final String json, final Class<T> type) {
        try {
            return MAPPER.readValue(json, type);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON deserialization failed", e);
        }
    }

    /**
     * Convert a value (e.g. a JsonNode) to the given type using Jackson conversion.
     */
    public static <T> T convertValue(final JsonNode node, final Class<T> type) {
        return MAPPER.convertValue(node, type);
    }
}
