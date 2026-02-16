package com.lauriewired.mcp.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ParamTypeTest {

    // =========================================================================
    // inferFrom tests
    // =========================================================================

    @Test
    void testInferFrom_String() {
        assertEquals(ParamType.STRING, ParamType.inferFrom(String.class));
    }

    @Test
    void testInferFrom_Int() {
        assertEquals(ParamType.INTEGER, ParamType.inferFrom(int.class));
    }

    @Test
    void testInferFrom_Integer() {
        assertEquals(ParamType.INTEGER, ParamType.inferFrom(Integer.class));
    }

    @Test
    void testInferFrom_Boolean() {
        assertEquals(ParamType.BOOLEAN, ParamType.inferFrom(boolean.class));
    }

    @Test
    void testInferFrom_BooleanWrapper() {
        assertEquals(ParamType.BOOLEAN, ParamType.inferFrom(Boolean.class));
    }

    @Test
    void testInferFrom_Long() {
        assertEquals(ParamType.LONG, ParamType.inferFrom(long.class));
    }

    @Test
    void testInferFrom_LongWrapper() {
        assertEquals(ParamType.LONG, ParamType.inferFrom(Long.class));
    }

    // Use fields to get parameterized types
    @SuppressWarnings("unused")
    private Map<String, String> stringMap;
    @SuppressWarnings("unused")
    private Map<String, Long> longMap;
    @SuppressWarnings("unused")
    private List<String[]> pairList;

    @Test
    void testInferFrom_StringMap() throws Exception {
        Type type = getClass().getDeclaredField("stringMap").getGenericType();
        assertEquals(ParamType.STRING_MAP, ParamType.inferFrom(type));
    }

    @Test
    void testInferFrom_LongMap() throws Exception {
        Type type = getClass().getDeclaredField("longMap").getGenericType();
        assertEquals(ParamType.LONG_MAP, ParamType.inferFrom(type));
    }

    @Test
    void testInferFrom_StringPairList() throws Exception {
        Type type = getClass().getDeclaredField("pairList").getGenericType();
        assertEquals(ParamType.STRING_PAIR_LIST, ParamType.inferFrom(type));
    }

    // =========================================================================
    // parseFromString tests
    // =========================================================================

    @Test
    void testParseFromString_String() {
        assertEquals("hello", ParamType.STRING.parseFromString("hello", "default"));
    }

    @Test
    void testParseFromString_StringNull() {
        assertEquals("default", ParamType.STRING.parseFromString(null, "default"));
    }

    @Test
    void testParseFromString_StringEmpty() {
        assertEquals("default", ParamType.STRING.parseFromString("", "default"));
    }

    @Test
    void testParseFromString_Integer() {
        assertEquals(42, ParamType.INTEGER.parseFromString("42", 0));
    }

    @Test
    void testParseFromString_IntegerInvalid() {
        assertEquals(0, ParamType.INTEGER.parseFromString("abc", 0));
    }

    @Test
    void testParseFromString_Long() {
        assertEquals(12345678901L, ParamType.LONG.parseFromString("12345678901", 0L));
    }

    @Test
    void testParseFromString_LongHex() {
        assertEquals(255L, ParamType.LONG.parseFromString("0xFF", 0L));
        assertEquals(255L, ParamType.LONG.parseFromString("0XFF", 0L));
    }

    @Test
    void testParseFromString_LongNull() {
        assertEquals(42L, ParamType.LONG.parseFromString(null, 42L));
    }

    @Test
    void testParseFromString_LongInvalid() {
        assertEquals(0L, ParamType.LONG.parseFromString("abc", 0L));
    }

    @Test
    void testParseFromString_Boolean() {
        assertEquals(true, ParamType.BOOLEAN.parseFromString("true", false));
        assertEquals(false, ParamType.BOOLEAN.parseFromString("false", true));
    }

    // =========================================================================
    // toJsonSchemaMap tests
    // =========================================================================

    @Test
    void testToJsonSchemaMap_String() {
        var schema = ParamType.STRING.toJsonSchemaMap("A name", true, null);
        assertEquals("string", schema.get("type"));
        assertEquals("A name", schema.get("description"));
    }

    @Test
    void testToJsonSchemaMap_IntegerWithDefault() {
        var schema = ParamType.INTEGER.toJsonSchemaMap("Start", false, "0");
        assertEquals("integer", schema.get("type"));
        assertEquals(0L, schema.get("default"));
    }

    @Test
    void testToJsonSchemaMap_Long() {
        var schema = ParamType.LONG.toJsonSchemaMap("Numeric value", true, null);
        assertEquals("integer", schema.get("type"));
        assertEquals("Numeric value", schema.get("description"));
    }

    @Test
    void testToJsonSchemaMap_LongWithDefault() {
        var schema = ParamType.LONG.toJsonSchemaMap("Amount", false, "100");
        assertEquals("integer", schema.get("type"));
        assertEquals(100L, schema.get("default"));
    }

    @Test
    void testToJsonSchemaMap_BooleanWithDefault() {
        var schema = ParamType.BOOLEAN.toJsonSchemaMap("A flag", false, "true");
        assertEquals("boolean", schema.get("type"));
        assertEquals(true, schema.get("default"));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testToJsonSchemaMap_StringMap() {
        var schema = ParamType.STRING_MAP.toJsonSchemaMap("Renames", true, null);
        assertEquals("object", schema.get("type"));
        var addlProps = (Map<String, Object>) schema.get("additionalProperties");
        assertEquals("string", addlProps.get("type"));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testToJsonSchemaMap_LongMap() {
        var schema = ParamType.LONG_MAP.toJsonSchemaMap("Values", true, null);
        assertEquals("object", schema.get("type"));
        var addlProps = (Map<String, Object>) schema.get("additionalProperties");
        assertEquals("integer", addlProps.get("type"));
    }

    @Test
    void testToJsonSchemaMap_StringPairList() {
        var schema = ParamType.STRING_PAIR_LIST.toJsonSchemaMap("Fields", false, null);
        assertEquals("array", schema.get("type"));
        assertTrue(schema.containsKey("items"));
    }
}
