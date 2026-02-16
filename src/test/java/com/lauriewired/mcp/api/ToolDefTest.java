package com.lauriewired.mcp.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import org.junit.jupiter.api.Test;

class ToolDefTest {

    // =========================================================================
    // camelToSnake tests
    // =========================================================================

    @Test
    void testCamelToSnake_SimpleMethod() {
        assertEquals("get_function_code", ToolDef.camelToSnake("getFunctionCode"));
    }

    @Test
    void testCamelToSnake_MultipleWords() {
        assertEquals("list_references_from", ToolDef.camelToSnake("listReferencesFrom"));
    }

    @Test
    void testCamelToSnake_SearchFunctions() {
        assertEquals("search_functions_by_name", ToolDef.camelToSnake("searchFunctionsByName"));
    }

    @Test
    void testCamelToSnake_ParamName() {
        assertEquals("function_identifier", ToolDef.camelToSnake("functionIdentifier"));
    }

    @Test
    void testCamelToSnake_BooleanParam() {
        assertEquals("as_string", ToolDef.camelToSnake("asString"));
    }

    @Test
    void testCamelToSnake_SingleWord() {
        assertEquals("mode", ToolDef.camelToSnake("mode"));
    }

    @Test
    void testCamelToSnake_AllLowercase() {
        assertEquals("query", ToolDef.camelToSnake("query"));
    }

    @Test
    void testCamelToSnake_WithNumbers() {
        assertEquals("field0_0x0", ToolDef.camelToSnake("field0_0x0"));
    }

    // =========================================================================
    // fromMethod tests
    // =========================================================================

    // Test helper class with annotated methods
    @SuppressWarnings("unused")
    static class TestTools {
        @McpTool(description = "A simple no-param tool")
        private String getProgramInfo() {
            return "info";
        }

        @McpTool(description = "Tool with params")
        private String getFunctionCode(
                @Param("Function name or address") String functionIdentifier,
                @Param(value = "Output format", defaultValue = "C") String mode) {
            return "code";
        }

        @McpTool(post = true, description = "A POST tool with map")
        private String renameVariables(
                @Param("Function name") String functionIdentifier,
                @Param("Map of renames") Map<String, String> renames) {
            return "ok";
        }

        @McpTool(name = "custom_name", description = "Tool with custom name")
        private String myCustomTool() {
            return "custom";
        }

        @McpTool(description = "Tool with int and boolean")
        private String readMemory(
                @Param("Address") String address,
                @Param(value = "Bytes to read", defaultValue = "16") int size,
                @Param(value = "As string", defaultValue = "true") boolean asString) {
            return "mem";
        }
    }

    @Test
    void testFromMethod_NoParams() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getProgramInfo");
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        assertEquals("get_program_info", def.getName());
        assertEquals(0, def.getParams().size());
        assertFalse(def.isPost());
    }

    @Test
    void testFromMethod_WithParams() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getFunctionCode", String.class, String.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        assertEquals("get_function_code", def.getName());
        assertFalse(def.isPost());
        assertEquals(2, def.getParams().size());

        ToolParamDef p0 = def.getParams().get(0);
        assertEquals("function_identifier", p0.name());
        assertEquals(ParamType.STRING, p0.type());
        assertTrue(p0.required());

        ToolParamDef p1 = def.getParams().get(1);
        assertEquals("mode", p1.name());
        assertEquals(ParamType.STRING, p1.type());
        assertFalse(p1.required());
        assertEquals("C", p1.defaultValue());
    }

    @Test
    void testFromMethod_PostWithMap() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("renameVariables", String.class, Map.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        assertEquals("rename_variables", def.getName());
        assertTrue(def.isPost());
        assertEquals(2, def.getParams().size());

        ToolParamDef p1 = def.getParams().get(1);
        assertEquals("renames", p1.name());
        assertEquals(ParamType.STRING_MAP, p1.type());
    }

    @Test
    void testFromMethod_CustomName() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("myCustomTool");
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        assertEquals("custom_name", def.getName());
    }

    @Test
    void testFromMethod_IntAndBooleanParams() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("readMemory", String.class, int.class, boolean.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        assertEquals("read_memory", def.getName());
        assertEquals(3, def.getParams().size());

        ToolParamDef sizeParam = def.getParams().get(1);
        assertEquals("size", sizeParam.name());
        assertEquals(ParamType.INTEGER, sizeParam.type());
        assertFalse(sizeParam.required());
        assertEquals(16, sizeParam.defaultValue());

        ToolParamDef boolParam = def.getParams().get(2);
        assertEquals("as_string", boolParam.name());
        assertEquals(ParamType.BOOLEAN, boolParam.type());
        assertFalse(boolParam.required());
        assertEquals(true, boolParam.defaultValue());
    }

    // =========================================================================
    // LONG type support tests
    // =========================================================================

    @SuppressWarnings("unused")
    static class LongTools {
        @McpTool(post = true, description = "Tool with long param")
        private String addEnumValue(
                @Param("Enum name") String enumName,
                @Param("Value name") String valueName,
                @Param("Numeric value") long value) {
            return "ok";
        }

        @McpTool(description = "Tool with Long wrapper")
        private String readLong(
                @Param(value = "Some long value", defaultValue = "42") Long amount) {
            return "ok";
        }
    }

    @Test
    void testFromMethod_LongParam() throws Exception {
        Method method = LongTools.class.getDeclaredMethod("addEnumValue", String.class, String.class, long.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        assertEquals("add_enum_value", def.getName());
        assertTrue(def.isPost());
        assertEquals(3, def.getParams().size());

        ToolParamDef valueParam = def.getParams().get(2);
        assertEquals("value", valueParam.name());
        assertEquals(ParamType.LONG, valueParam.type());
        assertTrue(valueParam.required());
    }

    @Test
    void testFromMethod_LongWrapperWithDefault() throws Exception {
        Method method = LongTools.class.getDeclaredMethod("readLong", Long.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        ToolParamDef p = def.getParams().get(0);
        assertEquals(ParamType.LONG, p.type());
        assertFalse(p.required());
        assertEquals(42L, p.defaultValue());
    }

    // =========================================================================
    // JSON Schema generation tests
    // =========================================================================

    @Test
    void testToInputSchemaJson_NoParams() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getProgramInfo");
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        String schema = def.toInputSchemaJson();
        assertEquals("{\"type\":\"object\"}", schema);
    }

    @Test
    void testToInputSchemaJson_WithRequired() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getFunctionCode", String.class, String.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        String schema = def.toInputSchemaJson();
        assertTrue(schema.contains("\"function_identifier\""));
        assertTrue(schema.contains("\"mode\""));
        assertTrue(schema.contains("\"required\""));
        assertTrue(schema.contains("\"function_identifier\""));
        // mode should not be in required since it has a default
        assertTrue(schema.contains("\"default\":\"C\""));
    }

    @Test
    void testToToolJson_Structure() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getProgramInfo");
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        String json = def.toToolJson();
        assertTrue(json.contains("\"name\":\"get_program_info\""));
        assertTrue(json.contains("\"description\":"));
        assertTrue(json.contains("\"method\":\"GET\""));
        assertTrue(json.contains("\"inputSchema\":"));
    }

    @Test
    void testDescriptionIncludesAutoParameters() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getFunctionCode", String.class, String.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        String desc = def.getDescription();
        assertTrue(desc.contains("Parameters:"));
        assertTrue(desc.contains("function_identifier:"));
        assertTrue(desc.contains("mode:"));
    }

    // =========================================================================
    // parseParams tests (GET query params)
    // =========================================================================

    private HttpExchange mockGetExchange(String query) {
        HttpExchange exchange = mock(HttpExchange.class);
        when(exchange.getRequestURI()).thenReturn(URI.create("/test" + (query != null ? "?" + query : "")));
        when(exchange.getRequestMethod()).thenReturn("GET");
        return exchange;
    }

    private HttpExchange mockPostExchange(String body) {
        HttpExchange exchange = mock(HttpExchange.class);
        when(exchange.getRequestURI()).thenReturn(URI.create("/test"));
        when(exchange.getRequestMethod()).thenReturn("POST");
        when(exchange.getRequestBody()).thenReturn(new ByteArrayInputStream(body.getBytes()));
        Headers headers = mock(Headers.class);
        when(exchange.getRequestHeaders()).thenReturn(headers);
        when(headers.getFirst("Content-Type")).thenReturn("application/x-www-form-urlencoded");
        return exchange;
    }

    @Test
    void testParseParams_GetWithAllParams() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getFunctionCode", String.class, String.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        HttpExchange exchange = mockGetExchange("function_identifier=main&mode=assembly");
        Map<String, Object> params = def.parseParams(exchange);

        assertEquals("main", params.get("function_identifier"));
        assertEquals("assembly", params.get("mode"));
    }

    @Test
    void testParseParams_GetWithDefaultValues() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getFunctionCode", String.class, String.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        // Only provide required param, mode should default to "C"
        HttpExchange exchange = mockGetExchange("function_identifier=main");
        Map<String, Object> params = def.parseParams(exchange);

        assertEquals("main", params.get("function_identifier"));
        assertEquals("C", params.get("mode"));
    }

    @Test
    void testParseParams_GetMissingRequiredParam() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getFunctionCode", String.class, String.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        // Missing function_identifier (required, no default)
        HttpExchange exchange = mockGetExchange("mode=assembly");
        Map<String, Object> params = def.parseParams(exchange);

        // Required param with no value should be null (no default)
        assertNull(params.get("function_identifier"));
        assertEquals("assembly", params.get("mode"));
    }

    @Test
    void testParseParams_GetIntegerParams() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("readMemory", String.class, int.class, boolean.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        HttpExchange exchange = mockGetExchange("address=0x401000&size=32&as_string=false");
        Map<String, Object> params = def.parseParams(exchange);

        assertEquals("0x401000", params.get("address"));
        assertEquals(32, params.get("size"));
        assertEquals(false, params.get("as_string"));
    }

    @Test
    void testParseParams_GetIntegerDefaults() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("readMemory", String.class, int.class, boolean.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        HttpExchange exchange = mockGetExchange("address=0x401000");
        Map<String, Object> params = def.parseParams(exchange);

        assertEquals("0x401000", params.get("address"));
        assertEquals(16, params.get("size"));  // default
        assertEquals(true, params.get("as_string"));  // default
    }

    @Test
    void testParseParams_GetMalformedInteger() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("readMemory", String.class, int.class, boolean.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        HttpExchange exchange = mockGetExchange("address=0x401000&size=notanumber");
        Map<String, Object> params = def.parseParams(exchange);

        // Malformed int should fall back to default
        assertEquals(16, params.get("size"));
    }

    @Test
    void testParseParams_NoParams() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("getProgramInfo");
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        HttpExchange exchange = mockGetExchange(null);
        Map<String, Object> params = def.parseParams(exchange);

        assertTrue(params.isEmpty());
    }

    // =========================================================================
    // parseParams tests (POST form-encoded, no complex types)
    // =========================================================================

    @SuppressWarnings("unused")
    static class PostSimpleTools {
        @McpTool(post = true, description = "POST tool with simple params")
        private String setComment(
                @Param("Address") String address,
                @Param("Comment text") String comment,
                @Param(value = "Comment type", defaultValue = "eol") String type) {
            return "ok";
        }
    }

    @Test
    void testParseParams_PostFormEncoded() throws Exception {
        Method method = PostSimpleTools.class.getDeclaredMethod("setComment", String.class, String.class, String.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        HttpExchange exchange = mockPostExchange("address=0x401000&comment=hello+world&type=pre");
        Map<String, Object> params = def.parseParams(exchange);

        assertEquals("0x401000", params.get("address"));
        assertEquals("hello world", params.get("comment"));
        assertEquals("pre", params.get("type"));
    }

    @Test
    void testParseParams_PostFormEncodedDefaults() throws Exception {
        Method method = PostSimpleTools.class.getDeclaredMethod("setComment", String.class, String.class, String.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        HttpExchange exchange = mockPostExchange("address=0x401000&comment=test");
        Map<String, Object> params = def.parseParams(exchange);

        assertEquals("0x401000", params.get("address"));
        assertEquals("test", params.get("comment"));
        assertEquals("eol", params.get("type"));  // default
    }

    // =========================================================================
    // parseParams tests (POST JSON with complex types)
    // =========================================================================

    @Test
    void testParseParams_PostJsonWithMap() throws Exception {
        Method method = TestTools.class.getDeclaredMethod("renameVariables", String.class, Map.class);
        McpTool ann = method.getAnnotation(McpTool.class);
        ToolDef def = ToolDef.fromMethod(method, ann);

        String jsonBody = "{\"function_identifier\":\"main\", \"renames\":{\"local_10\":\"buffer\", \"local_14\":\"size\"}}";
        HttpExchange exchange = mock(HttpExchange.class);
        when(exchange.getRequestBody()).thenReturn(new ByteArrayInputStream(jsonBody.getBytes()));

        Map<String, Object> params = def.parseParams(exchange);

        assertEquals("main", params.get("function_identifier"));
        @SuppressWarnings("unchecked")
        Map<String, String> renames = (Map<String, String>) params.get("renames");
        assertNotNull(renames);
        assertEquals("buffer", renames.get("local_10"));
        assertEquals("size", renames.get("local_14"));
    }

    // =========================================================================
    // parseParams tests for LONG type
    // =========================================================================

    @Test
    void testParseParams_GetLongParam() throws Exception {
        // Long params go through parseFromString for GET
        // Test via ParamType directly since GET uses parseFromString
        Object result = ParamType.LONG.parseFromString("12345678901", null);
        assertEquals(12345678901L, result);
    }

    @Test
    void testParseParams_GetLongHexParam() throws Exception {
        Object result = ParamType.LONG.parseFromString("0xFF", null);
        assertEquals(255L, result);
    }

    @Test
    void testParseParams_GetLongInvalid() throws Exception {
        Object result = ParamType.LONG.parseFromString("notanumber", 0L);
        assertEquals(0L, result);
    }

    @Test
    void testParseParams_GetLongNull() throws Exception {
        Object result = ParamType.LONG.parseFromString(null, 42L);
        assertEquals(42L, result);
    }
}
