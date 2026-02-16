package com.lauriewired.mcp.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JsonBuilderTest {

    @Test
    void testEmptyObject() {
        assertEquals("{}", JsonBuilder.object().build());
    }

    @Test
    void testStringValue() {
        String json = JsonBuilder.object().put("name", "main").build();
        assertEquals("{\"name\": \"main\"}", json);
    }

    @Test
    void testIntValue() {
        String json = JsonBuilder.object().put("count", 42).build();
        assertEquals("{\"count\": 42}", json);
    }

    @Test
    void testLongValue() {
        String json = JsonBuilder.object().put("size", 100000000000L).build();
        assertEquals("{\"size\": 100000000000}", json);
    }

    @Test
    void testBooleanValue() {
        String json = JsonBuilder.object().put("active", true).build();
        assertEquals("{\"active\": true}", json);
    }

    @Test
    void testNullString() {
        String json = JsonBuilder.object().put("comment", (String) null).build();
        assertEquals("{\"comment\": null}", json);
    }

    @Test
    void testExplicitNull() {
        String json = JsonBuilder.object().putNull("value").build();
        assertEquals("{\"value\": null}", json);
    }

    @Test
    void testPutIfNotNull_present() {
        String json = JsonBuilder.object().putIfNotNull("opt", "yes").build();
        assertEquals("{\"opt\": \"yes\"}", json);
    }

    @Test
    void testPutIfNotNull_absent() {
        String json = JsonBuilder.object().putIfNotNull("opt", null).build();
        assertEquals("{}", json);
    }

    @Test
    void testMultipleValues() {
        String json = JsonBuilder.object()
                .put("name", "main")
                .put("address", "00401000")
                .put("count", 42)
                .put("active", true)
                .build();
        assertEquals("{\"name\": \"main\", \"address\": \"00401000\", \"count\": 42, \"active\": true}", json);
    }

    @Test
    void testNestedObject() {
        String json = JsonBuilder.object()
                .putObject("nested", JsonBuilder.object().put("x", 1).put("y", 2))
                .build();
        assertEquals("{\"nested\": {\"x\": 1, \"y\": 2}}", json);
    }

    @Test
    void testNestedArray() {
        String json = JsonBuilder.object()
                .putArray("items", JsonBuilder.array().addString("a").addString("b"))
                .build();
        assertEquals("{\"items\": [\"a\", \"b\"]}", json);
    }

    @Test
    void testPutRaw() {
        String json = JsonBuilder.object()
                .putRaw("data", "{\"x\": 1}")
                .build();
        assertEquals("{\"data\": {\"x\": 1}}", json);
    }

    @Test
    void testStringEscaping() {
        String json = JsonBuilder.object().put("text", "hello \"world\"\nnewline").build();
        assertEquals("{\"text\": \"hello \\\"world\\\"\\nnewline\"}", json);
    }

    // ── Array builder tests ────────────────────────────────────────────

    @Test
    void testEmptyArray() {
        assertEquals("[]", JsonBuilder.array().build());
    }

    @Test
    void testArrayOfStrings() {
        String json = JsonBuilder.array().addString("a").addString("b").addString("c").build();
        assertEquals("[\"a\", \"b\", \"c\"]", json);
    }

    @Test
    void testArrayOfInts() {
        String json = JsonBuilder.array().addInt(1).addInt(2).addInt(3).build();
        assertEquals("[1, 2, 3]", json);
    }

    @Test
    void testArrayOfMixed() {
        String json = JsonBuilder.array()
                .addString("hello")
                .addInt(42)
                .addBoolean(true)
                .addNull()
                .build();
        assertEquals("[\"hello\", 42, true, null]", json);
    }

    @Test
    void testArrayOfObjects() {
        String json = JsonBuilder.array()
                .addObject(JsonBuilder.object().put("name", "a"))
                .addObject(JsonBuilder.object().put("name", "b"))
                .build();
        assertEquals("[{\"name\": \"a\"}, {\"name\": \"b\"}]", json);
    }

    @Test
    void testArrayAddRaw() {
        String json = JsonBuilder.array()
                .addRaw("{\"x\": 1}")
                .addRaw("{\"y\": 2}")
                .build();
        assertEquals("[{\"x\": 1}, {\"y\": 2}]", json);
    }

    @Test
    void testNestedArrayInArray() {
        String json = JsonBuilder.array()
                .addArray(JsonBuilder.array().addInt(1).addInt(2))
                .addArray(JsonBuilder.array().addInt(3).addInt(4))
                .build();
        assertEquals("[[1, 2], [3, 4]]", json);
    }

    @Test
    void testArrayAddLong() {
        String json = JsonBuilder.array().addLong(999999999999L).build();
        assertEquals("[999999999999]", json);
    }

    @Test
    void testArrayNullString() {
        String json = JsonBuilder.array().addString(null).build();
        assertEquals("[null]", json);
    }

    @Test
    void testComplexNesting() {
        String json = JsonBuilder.object()
                .put("function", "main")
                .put("entryPoint", "00401000")
                .put("depth", 2)
                .putArray("callers", JsonBuilder.array()
                        .addObject(JsonBuilder.object()
                                .put("name", "_start")
                                .put("address", "00400000")
                                .putArray("callers", JsonBuilder.array())))
                .putArray("callees", JsonBuilder.array()
                        .addObject(JsonBuilder.object()
                                .put("name", "printf")
                                .put("address", "00401234")
                                .putArray("callees", JsonBuilder.array())))
                .build();
        assertTrue(json.contains("\"function\": \"main\""));
        assertTrue(json.contains("\"callers\": [{\"name\": \"_start\""));
        assertTrue(json.contains("\"callees\": [{\"name\": \"printf\""));
    }
}
