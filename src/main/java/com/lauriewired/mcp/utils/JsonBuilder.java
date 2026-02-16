package com.lauriewired.mcp.utils;

/**
 * Fluent API for building JSON without external libraries.
 * All string values are auto-escaped via {@link HttpUtils#escapeJson(String)}.
 *
 * <pre>
 * JsonBuilder.object()
 *     .put("name", "main").put("address", "00401000").put("count", 42)
 *     .put("active", true).putNull("comment")
 *     .putObject("nested", JsonBuilder.object().put("x", 1))
 *     .putArray("items", JsonBuilder.array().addString("a"))
 *     .build()
 * </pre>
 */
public final class JsonBuilder {

    private final StringBuilder sb;
    private boolean hasEntry;

    private JsonBuilder() {
        sb = new StringBuilder();
        sb.append('{');
        hasEntry = false;
    }

    /** Start building a JSON object. */
    public static JsonBuilder object() {
        return new JsonBuilder();
    }

    /** Start building a JSON array. */
    public static JsonArrayBuilder array() {
        return new JsonArrayBuilder();
    }

    // ── String ──────────────────────────────────────────────────────────

    /** Add a string key-value pair. Null values are written as JSON null. */
    public JsonBuilder put(String key, String value) {
        appendKey(key);
        if (value == null) {
            sb.append("null");
        } else {
            sb.append('"').append(HttpUtils.escapeJson(value)).append('"');
        }
        return this;
    }

    /** Add a string value only if it is non-null. */
    public JsonBuilder putIfNotNull(String key, String value) {
        if (value != null) put(key, value);
        return this;
    }

    // ── Numeric ─────────────────────────────────────────────────────────

    /** Add an int key-value pair. */
    public JsonBuilder put(String key, int value) {
        appendKey(key);
        sb.append(value);
        return this;
    }

    /** Add a long key-value pair. */
    public JsonBuilder put(String key, long value) {
        appendKey(key);
        sb.append(value);
        return this;
    }

    // ── Boolean ─────────────────────────────────────────────────────────

    /** Add a boolean key-value pair. */
    public JsonBuilder put(String key, boolean value) {
        appendKey(key);
        sb.append(value);
        return this;
    }

    // ── Null ────────────────────────────────────────────────────────────

    /** Add an explicit null value. */
    public JsonBuilder putNull(String key) {
        appendKey(key);
        sb.append("null");
        return this;
    }

    // ── Nested structures ───────────────────────────────────────────────

    /** Add a nested object built by another JsonBuilder. */
    public JsonBuilder putObject(String key, JsonBuilder nested) {
        appendKey(key);
        sb.append(nested.build());
        return this;
    }

    /** Add a nested array built by a JsonArrayBuilder. */
    public JsonBuilder putArray(String key, JsonArrayBuilder arrayBuilder) {
        appendKey(key);
        sb.append(arrayBuilder.build());
        return this;
    }

    // ── Raw JSON ────────────────────────────────────────────────────────

    /** Add a pre-built raw JSON value (must be valid JSON). */
    public JsonBuilder putRaw(String key, String rawJson) {
        appendKey(key);
        sb.append(rawJson);
        return this;
    }

    // ── Build ───────────────────────────────────────────────────────────

    /** Finish building and return the JSON string. */
    public String build() {
        sb.append('}');
        return sb.toString();
    }

    private void appendKey(String key) {
        if (hasEntry) sb.append(", ");
        sb.append('"').append(HttpUtils.escapeJson(key)).append("\": ");
        hasEntry = true;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  JSON Array Builder
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Fluent builder for JSON arrays.
     */
    public static final class JsonArrayBuilder {
        private final StringBuilder sb;
        private boolean hasEntry;

        private JsonArrayBuilder() {
            sb = new StringBuilder();
            sb.append('[');
            hasEntry = false;
        }

        private void sep() {
            if (hasEntry) sb.append(", ");
            hasEntry = true;
        }

        /** Add a string element. */
        public JsonArrayBuilder addString(String value) {
            sep();
            if (value == null) {
                sb.append("null");
            } else {
                sb.append('"').append(HttpUtils.escapeJson(value)).append('"');
            }
            return this;
        }

        /** Add an int element. */
        public JsonArrayBuilder addInt(int value) {
            sep();
            sb.append(value);
            return this;
        }

        /** Add a long element. */
        public JsonArrayBuilder addLong(long value) {
            sep();
            sb.append(value);
            return this;
        }

        /** Add a boolean element. */
        public JsonArrayBuilder addBoolean(boolean value) {
            sep();
            sb.append(value);
            return this;
        }

        /** Add a null element. */
        public JsonArrayBuilder addNull() {
            sep();
            sb.append("null");
            return this;
        }

        /** Add a nested object. */
        public JsonArrayBuilder addObject(JsonBuilder nested) {
            sep();
            sb.append(nested.build());
            return this;
        }

        /** Add a nested array. */
        public JsonArrayBuilder addArray(JsonArrayBuilder nested) {
            sep();
            sb.append(nested.build());
            return this;
        }

        /** Add pre-built raw JSON. */
        public JsonArrayBuilder addRaw(String rawJson) {
            sep();
            sb.append(rawJson);
            return this;
        }

        /** Finish building and return the JSON array string. */
        public String build() {
            sb.append(']');
            return sb.toString();
        }
    }
}
