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
    // toJsonSchemaFragment tests
    // =========================================================================

    @Test
    void testToJsonSchemaFragment_String() {
        String fragment = ParamType.STRING.toJsonSchemaFragment("name", "A name", true, null);
        assertTrue(fragment.contains("\"name\""));
        assertTrue(fragment.contains("\"type\": \"string\""));
        assertTrue(fragment.contains("\"description\": \"A name\""));
    }

    @Test
    void testToJsonSchemaFragment_IntegerWithDefault() {
        String fragment = ParamType.INTEGER.toJsonSchemaFragment("offset", "Start", false, "0");
        assertTrue(fragment.contains("\"type\": \"integer\""));
        assertTrue(fragment.contains("\"default\": 0"));
    }

    @Test
    void testToJsonSchemaFragment_Long() {
        String fragment = ParamType.LONG.toJsonSchemaFragment("value", "Numeric value", true, null);
        assertTrue(fragment.contains("\"type\": \"integer\""));
        assertTrue(fragment.contains("\"description\": \"Numeric value\""));
    }

    @Test
    void testToJsonSchemaFragment_LongWithDefault() {
        String fragment = ParamType.LONG.toJsonSchemaFragment("amount", "Amount", false, "100");
        assertTrue(fragment.contains("\"type\": \"integer\""));
        assertTrue(fragment.contains("\"default\": 100"));
    }

    @Test
    void testToJsonSchemaFragment_BooleanWithDefault() {
        String fragment = ParamType.BOOLEAN.toJsonSchemaFragment("flag", "A flag", false, "true");
        assertTrue(fragment.contains("\"type\": \"boolean\""));
        assertTrue(fragment.contains("\"default\": true"));
    }

    @Test
    void testToJsonSchemaFragment_StringMap() {
        String fragment = ParamType.STRING_MAP.toJsonSchemaFragment("renames", "Renames", true, null);
        assertTrue(fragment.contains("\"type\": \"object\""));
        assertTrue(fragment.contains("\"additionalProperties\": {\"type\": \"string\"}"));
    }

    @Test
    void testToJsonSchemaFragment_LongMap() {
        String fragment = ParamType.LONG_MAP.toJsonSchemaFragment("values", "Values", true, null);
        assertTrue(fragment.contains("\"type\": \"object\""));
        assertTrue(fragment.contains("\"additionalProperties\": {\"type\": \"integer\"}"));
    }

    @Test
    void testToJsonSchemaFragment_StringPairList() {
        String fragment = ParamType.STRING_PAIR_LIST.toJsonSchemaFragment("fields", "Fields", false, null);
        assertTrue(fragment.contains("\"type\": \"array\""));
        assertTrue(fragment.contains("\"items\":"));
    }
}
