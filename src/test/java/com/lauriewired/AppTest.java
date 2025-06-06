package com.lauriewired;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpExchange;
import com.lauriewired.mcp.utils.HttpUtils;

/**
 * Unit test for simple App.
 */
public class AppTest {
    /**
     * Rigourous Test :-)
     */
    @Test
    @DisplayName("Simple test that always passes")
    public void testApp()
    {
        assertTrue(true);
    }
    
    /**
     * Tests for paginateList method in HttpUtils
     */
    @Test
    @DisplayName("Test pagination functionality")
    public void testPaginateList() {
        // Test empty list
        List<String> emptyList = new ArrayList<>();
        String emptyResult = HttpUtils.paginateList(emptyList, 0, 10);
        assertTrue(emptyResult.isEmpty());

        // Test list smaller than page size
        List<String> smallList = Arrays.asList("a", "b", "c");
        String smallResult = HttpUtils.paginateList(smallList, 0, 5);
        assertEquals("a\nb\nc", smallResult);
        
        // Test normal pagination - first page
        List<String> testList = Arrays.asList("item1", "item2", "item3", "item4", "item5", "item6", "item7", "item8", "item9", "item10");
        String firstPage = HttpUtils.paginateList(testList, 0, 3);
        assertEquals("item1\nitem2\nitem3", firstPage);
        
        // Test normal pagination - second page
        String secondPage = HttpUtils.paginateList(testList, 3, 3);
        assertEquals("item4\nitem5\nitem6", secondPage);
        
        // Test normal pagination - last page with fewer items
        String lastPage = HttpUtils.paginateList(testList, 8, 3);
        assertEquals("item9\nitem10", lastPage);
        
        // Test offset beyond list size
        String beyondSize = HttpUtils.paginateList(testList, 20, 5);
        assertTrue(beyondSize.isEmpty());
        
        // Test negative offset (should be treated as 0)
        String negativeOffset = HttpUtils.paginateList(testList, -5, 3);
        assertEquals("item1\nitem2\nitem3", negativeOffset);
        
        // Test zero limit (should return empty string)
        String zeroLimit = HttpUtils.paginateList(testList, 0, 0);
        assertTrue(zeroLimit.isEmpty());
        
        // Test limit larger than list size
        String largeLimit = HttpUtils.paginateList(testList, 0, 20);
        assertEquals("item1\nitem2\nitem3\nitem4\nitem5\nitem6\nitem7\nitem8\nitem9\nitem10", largeLimit);
        
        // Test partial page at end with exact limit
        String partialExact = HttpUtils.paginateList(testList, 8, 2);
        assertEquals("item9\nitem10", partialExact);
        
        // Test offset at end of list
        String endOffset = HttpUtils.paginateList(testList, 10, 5);
        assertTrue(endOffset.isEmpty());
    }
    
    /**
     * Tests for parseQueryParams method in HttpUtils
     */
    @Test
    @DisplayName("Test query parameter parsing")
    public void testParseQueryParams() {
        // Test case 1: Empty query string
        HttpExchange emptyExchange = createMockHttpExchange(null);
        Map<String, String> emptyResult = HttpUtils.parseQueryParams(emptyExchange);
        assertTrue(emptyResult.isEmpty(), "Empty query should return empty map");
        
        // Test case 2: Single parameter
        HttpExchange singleParamExchange = createMockHttpExchange("param=value");
        Map<String, String> singleResult = HttpUtils.parseQueryParams(singleParamExchange);
        assertEquals(1, singleResult.size(), "Should have exactly one parameter");
        assertEquals("value", singleResult.get("param"), "Parameter value should match");
        
        // Test case 3: Multiple parameters
        HttpExchange multiParamExchange = createMockHttpExchange("first=1&second=2&third=3");
        Map<String, String> multiResult = HttpUtils.parseQueryParams(multiParamExchange);
        assertEquals(3, multiResult.size(), "Should have exactly three parameters");
        assertEquals("1", multiResult.get("first"), "First parameter value should match");
        assertEquals("2", multiResult.get("second"), "Second parameter value should match");
        assertEquals("3", multiResult.get("third"), "Third parameter value should match");
        
        // Test case 4: URL-encoded parameters
        HttpExchange encodedExchange = createMockHttpExchange("name=John+Doe&query=hello%20world");
        Map<String, String> encodedResult = HttpUtils.parseQueryParams(encodedExchange);
        assertEquals(2, encodedResult.size(), "Should have exactly two parameters");
        assertEquals("John Doe", encodedResult.get("name"), "Name should be properly decoded");
        assertEquals("hello world", encodedResult.get("query"), "Query should be properly decoded");
        
        // Test case 5: Special characters
        HttpExchange specialCharsExchange = createMockHttpExchange("param=%21%40%23%24%25%5E%26%2A%28%29");
        Map<String, String> specialCharsResult = HttpUtils.parseQueryParams(specialCharsExchange);
        assertEquals("!@#$%^&*()", specialCharsResult.get("param"), "Special characters should be properly decoded");
        
        // Test case 6: Question mark in parameter value
        HttpExchange questionMarkExchange = createMockHttpExchange("query=what%3Fwhere%3Fwhen%3F");
        Map<String, String> questionMarkResult = HttpUtils.parseQueryParams(questionMarkExchange);
        assertEquals("what?where?when?", questionMarkResult.get("query"), "Question marks should be properly decoded");
        
        // Test case 7: Parameter with complex search query
        HttpExchange searchQueryExchange = createMockHttpExchange("search=function%3Fpattern%3D%22main%22");
        Map<String, String> searchQueryResult = HttpUtils.parseQueryParams(searchQueryExchange);
        assertEquals("function?pattern=\"main\"", searchQueryResult.get("search"), "Complex query with question marks should be properly decoded");
    }
    
    /**
     * Helper method to create a mock HttpExchange with a specific query string
     */
    private HttpExchange createMockHttpExchange(String queryString) {
        return new MockHttpExchange(queryString);
    }
    
    /**
     * Tests for parsePostParams method in HttpUtils
     */
    @Test
    @DisplayName("Test POST parameter parsing")
    public void testParsePostParams() throws IOException {
        // Test case 1: Empty body
        HttpExchange emptyExchange = createMockHttpExchangeWithBody("");
        Map<String, String> emptyResult = HttpUtils.parsePostParams(emptyExchange);
        assertTrue(emptyResult.isEmpty(), "Empty body should return empty map");
        
        // Test case 2: Single parameter
        HttpExchange singleParamExchange = createMockHttpExchangeWithBody("param=value");
        Map<String, String> singleResult = HttpUtils.parsePostParams(singleParamExchange);
        assertEquals(1, singleResult.size(), "Should have exactly one parameter");
        assertEquals("value", singleResult.get("param"), "Parameter value should match");
        
        // Test case 3: Multiple parameters
        HttpExchange multiParamExchange = createMockHttpExchangeWithBody("first=1&second=2&third=3");
        Map<String, String> multiResult = HttpUtils.parsePostParams(multiParamExchange);
        assertEquals(3, multiResult.size(), "Should have exactly three parameters");
        assertEquals("1", multiResult.get("first"), "First parameter value should match");
        assertEquals("2", multiResult.get("second"), "Second parameter value should match");
        assertEquals("3", multiResult.get("third"), "Third parameter value should match");
        
        // Test case 4: URL-encoded parameters
        HttpExchange encodedExchange = createMockHttpExchangeWithBody("name=John+Doe&query=hello%20world");
        Map<String, String> encodedResult = HttpUtils.parsePostParams(encodedExchange);
        assertEquals(2, encodedResult.size(), "Should have exactly two parameters");
        assertEquals("John Doe", encodedResult.get("name"), "Name should be properly decoded");
        assertEquals("hello world", encodedResult.get("query"), "Query should be properly decoded");
        
        // Test case 5: Special characters
        HttpExchange specialCharsExchange = createMockHttpExchangeWithBody("param=%21%40%23%24%25%5E%26%2A%28%29");
        Map<String, String> specialCharsResult = HttpUtils.parsePostParams(specialCharsExchange);
        assertEquals("!@#$%^&*()", specialCharsResult.get("param"), "Special characters should be properly decoded");
        
        // Test case 6: Malformed parameters (missing value)
        HttpExchange malformedExchange = createMockHttpExchangeWithBody("param1=value1&param2=&param3=value3");
        Map<String, String> malformedResult = HttpUtils.parsePostParams(malformedExchange);
        assertEquals(3, malformedResult.size(), "Should have three parameters");
        assertEquals("value1", malformedResult.get("param1"), "First parameter value should match");
        assertEquals("", malformedResult.get("param2"), "Second parameter value should be empty");
        assertEquals("value3", malformedResult.get("param3"), "Third parameter value should match");
        
        // Test case 7: Invalid URL encoding (should skip the invalid parameter but process valid ones)
        HttpExchange invalidEncodingExchange = createMockHttpExchangeWithBody("valid=ok&invalid=%invalid&another=good");
        Map<String, String> invalidEncodingResult = HttpUtils.parsePostParams(invalidEncodingExchange);
        assertTrue(invalidEncodingResult.containsKey("valid"), "Valid parameter should be processed");
        assertTrue(invalidEncodingResult.containsKey("another"), "Valid parameter should be processed");
        assertEquals("ok", invalidEncodingResult.get("valid"), "Valid parameter value should match");
        assertEquals("good", invalidEncodingResult.get("another"), "Valid parameter value should match");
        
        // Test case 8: Duplicate keys (last one should win)
        HttpExchange duplicateKeysExchange = createMockHttpExchangeWithBody("key=value1&key=value2&key=value3");
        Map<String, String> duplicateKeysResult = HttpUtils.parsePostParams(duplicateKeysExchange);
        assertEquals(1, duplicateKeysResult.size(), "Should have one parameter");
        assertEquals("value3", duplicateKeysResult.get("key"), "Last value should be used");
        
        // Test case 9: Parameter with no equals sign
        HttpExchange noEqualsExchange = createMockHttpExchangeWithBody("param1=value1&justkey&param2=value2");
        Map<String, String> noEqualsResult = HttpUtils.parsePostParams(noEqualsExchange);
        assertEquals(2, noEqualsResult.size(), "Should have two valid parameters");
        assertEquals("value1", noEqualsResult.get("param1"), "First parameter value should match");
        assertEquals("value2", noEqualsResult.get("param2"), "Second parameter value should match");
        
        // Test case 10: Question mark in POST parameter value
        HttpExchange postQuestionMarkExchange = createMockHttpExchangeWithBody("filter=address%3F0x400000%3Fcode");
        Map<String, String> postQuestionMarkResult = HttpUtils.parsePostParams(postQuestionMarkExchange);
        assertEquals("address?0x400000?code", postQuestionMarkResult.get("filter"), "Question marks in POST parameters should be properly decoded");
        
        // Test case 11: POST parameter with multiple question marks and other special chars
        HttpExchange complexQueryExchange = createMockHttpExchangeWithBody("query=find%3Ffunction%3D%22main%22%3Faddress%3D0x400000");
        Map<String, String> complexQueryResult = HttpUtils.parsePostParams(complexQueryExchange);
        assertEquals("find?function=\"main\"?address=0x400000", complexQueryResult.get("query"), "Complex query with question marks should be properly decoded");
    }
    
    /**
     * Helper method to create a mock HttpExchange with a specific request body
     */
    private HttpExchange createMockHttpExchangeWithBody(String body) {
        return new MockHttpExchange(null, body);
    }
    
    /**
     * Mock implementation of HttpExchange for testing
     */
    private static class MockHttpExchange extends HttpExchange {
        private final String queryString;
        private final String requestBody;
        
        public MockHttpExchange(String queryString) {
            this(queryString, null);
        }
        
        public MockHttpExchange(String queryString, String requestBody) {
            this.queryString = queryString;
            this.requestBody = requestBody;
        }
        
        @Override
        public URI getRequestURI() {
            try {
                return URI.create("http://example.com/test" + (queryString != null ? "?" + queryString : ""));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        
        @Override
        public InputStream getRequestBody() {
            if (requestBody != null) {
                return new ByteArrayInputStream(requestBody.getBytes());
            }
            return new ByteArrayInputStream(new byte[0]);
        }
        
        // Implement required abstract methods with minimal implementations
        @Override public java.io.OutputStream getResponseBody() { return null; }
        @Override public void close() {}
        @Override public com.sun.net.httpserver.Headers getRequestHeaders() { return null; }
        @Override public com.sun.net.httpserver.Headers getResponseHeaders() { return null; }
        @Override public void sendResponseHeaders(int rCode, long responseLength) {}
        @Override public com.sun.net.httpserver.HttpContext getHttpContext() { return null; }
        @Override public String getRequestMethod() { return null; }
        @Override public com.sun.net.httpserver.HttpPrincipal getPrincipal() { return null; }
        @Override public String getProtocol() { return null; }
        @Override public java.net.InetSocketAddress getRemoteAddress() { return null; }
        @Override public java.net.InetSocketAddress getLocalAddress() { return null; }
        @Override public Object getAttribute(String name) { return null; }
        @Override public void setAttribute(String name, Object value) {}
        @Override public int getResponseCode() { return 200; } // Default response code
        @Override public void setStreams(java.io.InputStream i, java.io.OutputStream o) {} // No-op implementation
    }
}
