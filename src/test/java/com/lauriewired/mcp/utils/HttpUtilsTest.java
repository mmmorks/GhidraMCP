package com.lauriewired.mcp.utils;

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
        String input = "{\n\t\"name\": \"John Doe\",\n\t\"path\": \"C:\\\\Users\\\\john\"\n}";
        String result = HttpUtils.escapeJson(input);
        String expected = "{\\n\\t\\\"name\\\": \\\"John Doe\\\",\\n\\t\\\"path\\\": \\\"C:\\\\\\\\Users\\\\\\\\john\\\"\\n}";
        assertEquals(expected, result);
    }
    
    @Test
    @DisplayName("escapeJson handles Unicode characters")
    void testEscapeJson_Unicode() {
        String input = "Hello 世界 🌍";
        String result = HttpUtils.escapeJson(input);
        // Apache Commons Text should handle Unicode appropriately
        assertNotNull(result);
        assertTrue(result.contains("Hello"));
    }
}
