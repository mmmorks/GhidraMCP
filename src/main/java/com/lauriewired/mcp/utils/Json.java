package com.lauriewired.mcp.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Shared ObjectMapper singleton for JSON serialization.
 * Configured with NON_NULL inclusion to omit null fields.
 */
public final class Json {
    private static final ObjectMapper MAPPER = new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private Json() {}

    /**
     * Serialize an object to a JSON string.
     *
     * @param value the object to serialize
     * @return JSON string representation
     * @throws RuntimeException if serialization fails
     */
    public static String serialize(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON serialization failed", e);
        }
    }

    /**
     * Get the shared ObjectMapper instance.
     */
    public static ObjectMapper mapper() {
        return MAPPER;
    }
}
