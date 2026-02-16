package com.lauriewired.mcp.utils;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HttpUtils JSON escaping functionality
 */
public class HttpUtilsTest {
    
    @Test
    @DisplayName("escapeJson handles null input")
    void testEscapeJson_Null() {
        String result = HttpUtils.escapeJson(null);
        assertNull(result);
    }
    
    @Test
    @DisplayName("escapeJson handles empty string")
    void testEscapeJson_Empty() {
        String result = HttpUtils.escapeJson("");
        assertEquals("", result);
    }
    
    @Test
    @DisplayName("escapeJson handles string with no special characters")
    void testEscapeJson_NoSpecialChars() {
        String input = "Hello World";
        String result = HttpUtils.escapeJson(input);
        assertEquals("Hello World", result);
    }
    
    @Test
    @DisplayName("escapeJson escapes double quotes")
    void testEscapeJson_DoubleQuotes() {
        String input = "He said \"Hello\"";
        String result = HttpUtils.escapeJson(input);
        assertEquals("He said \\\"Hello\\\"", result);
    }
    
    @Test
    @DisplayName("escapeJson escapes backslashes")
    void testEscapeJson_Backslashes() {
        String input = "C:\\Users\\test\\file.txt";
        String result = HttpUtils.escapeJson(input);
        assertEquals("C:\\\\Users\\\\test\\\\file.txt", result);
    }
    
    @Test
    @DisplayName("escapeJson escapes newlines")
    void testEscapeJson_Newlines() {
        String input = "Line 1\nLine 2";
        String result = HttpUtils.escapeJson(input);
        assertEquals("Line 1\\nLine 2", result);
    }
    
    @Test
    @DisplayName("escapeJson escapes carriage returns")
    void testEscapeJson_CarriageReturns() {
        String input = "Line 1\rLine 2";
        String result = HttpUtils.escapeJson(input);
        assertEquals("Line 1\\rLine 2", result);
    }
    
    @Test
    @DisplayName("escapeJson escapes tabs")
    void testEscapeJson_Tabs() {
        String input = "Column1\tColumn2";
        String result = HttpUtils.escapeJson(input);
        assertEquals("Column1\\tColumn2", result);
    }
    
    @Test
    @DisplayName("escapeJson handles complex string with multiple special characters")
    void testEscapeJson_Complex() {
        String input = "{\n\t\"name\":\"John Doe\",\n\t\"path\":\"C:\\\\Users\\\\john\"\n}";
        String result = HttpUtils.escapeJson(input);
        String expected = "{\\n\\t\\\"name\\\":\\\"John Doe\\\",\\n\\t\\\"path\\\":\\\"C:\\\\\\\\Users\\\\\\\\john\\\"\\n}";
        assertEquals(expected, result);
    }
    
    @Test
    @DisplayName("escapeJson handles Unicode characters")
    void testEscapeJson_Unicode() {
        String input = "Hello 世界 🌍";
        String result = HttpUtils.escapeJson(input);
        assertNotNull(result);
        assertTrue(result.contains("Hello"));
    }

    // --- parseJsonBody tests ---

    @Test
    @DisplayName("parseJsonBody parses simple flat JSON")
    void testParseJsonBody_SimpleFlatJson() {
        String body = "{\"function_identifier\":\"main\", \"new_name\":\"entry\"}";
        Map<String, String> result = HttpUtils.parseJsonBody(body);
        assertEquals(2, result.size());
        assertEquals("main", result.get("function_identifier"));
        assertEquals("entry", result.get("new_name"));
    }

    @Test
    @DisplayName("parseJsonBody handles numeric and boolean values")
    void testParseJsonBody_NumericBooleanValues() {
        String body = "{\"address\":\"0x1000\", \"size\":42, \"clear_existing\":true}";
        Map<String, String> result = HttpUtils.parseJsonBody(body);
        assertEquals(3, result.size());
        assertEquals("0x1000", result.get("address"));
        assertEquals("42", result.get("size"));
        assertEquals("true", result.get("clear_existing"));
    }

    @Test
    @DisplayName("parseJsonBody handles escaped quotes in values")
    void testParseJsonBody_EscapedQuotes() {
        String body = "{\"prototype\":\"int func(char *msg, \\\"hello\\\")\"}";
        Map<String, String> result = HttpUtils.parseJsonBody(body);
        assertEquals("int func(char *msg, \"hello\")", result.get("prototype"));
    }

    @Test
    @DisplayName("parseJsonBody handles empty body")
    void testParseJsonBody_EmptyBody() {
        assertEquals(0, HttpUtils.parseJsonBody("").size());
        assertEquals(0, HttpUtils.parseJsonBody("{}").size());
        assertEquals(0, HttpUtils.parseJsonBody(null).size());
    }

    @Test
    @DisplayName("parseJsonBody skips null values")
    void testParseJsonBody_NullValues() {
        String body = "{\"name\":\"test\", \"extra\":null}";
        Map<String, String> result = HttpUtils.parseJsonBody(body);
        assertEquals(1, result.size());
        assertEquals("test", result.get("name"));
        assertFalse(result.containsKey("extra"));
    }

    @Test
    @DisplayName("parseJsonBody skips nested objects and arrays")
    void testParseJsonBody_NestedObjectsSkipped() {
        String body = "{\"name\":\"main\", \"renames\":{\"a\":\"b\"}, \"tag\":\"v1\"}";
        Map<String, String> result = HttpUtils.parseJsonBody(body);
        assertEquals(2, result.size());
        assertEquals("main", result.get("name"));
        assertEquals("v1", result.get("tag"));
        assertFalse(result.containsKey("renames"));
    }

    // --- escapeJson control chars ---

    @Test
    @DisplayName("escapeJson escapes backspace and form feed")
    void testEscapeJson_BackspaceFormFeed() {
        assertEquals("a\\bb\\fc", HttpUtils.escapeJson("a\bb\fc"));
    }

    @Test
    @DisplayName("escapeJson escapes low control characters as unicode")
    void testEscapeJson_ControlChars() {
        // U+0001 should become \u0001
        String input = "a\u0001b";
        String result = HttpUtils.escapeJson(input);
        assertEquals("a\\u0001b", result);
    }

    // --- isErrorResponse tests ---

    @Test
    @DisplayName("isErrorResponse detects error prefixes")
    void testIsErrorResponse_DetectsErrors() {
        assertTrue(HttpUtils.isErrorResponse("Error: something broke"));
        assertTrue(HttpUtils.isErrorResponse("Failed to do something"));
        assertTrue(HttpUtils.isErrorResponse("Invalid address"));
        assertTrue(HttpUtils.isErrorResponse("No program loaded"));
        assertTrue(HttpUtils.isErrorResponse("Function not found: main"));
        assertTrue(HttpUtils.isErrorResponse("Could not resolve address"));
    }

    @Test
    @DisplayName("isErrorResponse returns false for success messages")
    void testIsErrorResponse_SuccessMessages() {
        assertFalse(HttpUtils.isErrorResponse("Function renamed successfully"));
        assertFalse(HttpUtils.isErrorResponse("main\nprintf\nmalloc"));
        assertFalse(HttpUtils.isErrorResponse(""));
        assertFalse(HttpUtils.isErrorResponse(null));
    }
}
