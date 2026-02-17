package com.lauriewired.mcp.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import com.lauriewired.mcp.McpServerManager;
import com.lauriewired.mcp.services.AnalysisService;
import com.lauriewired.mcp.services.CommentService;
import com.lauriewired.mcp.services.DataTypeService;
import com.lauriewired.mcp.services.FunctionService;
import com.lauriewired.mcp.services.MemoryService;
import com.lauriewired.mcp.services.NamespaceService;
import com.lauriewired.mcp.services.ProgramService;
import com.lauriewired.mcp.services.SearchService;
import com.lauriewired.mcp.services.VariableService;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

@ExtendWith(MockitoExtension.class)
class ApiHandlerRegistryTest {

    @Mock
    private McpServerManager mockServerManager;

    @Mock
    private HttpServer mockHttpServer;

    @Mock
    private FunctionService mockFunctionService;

    @Mock
    private NamespaceService mockNamespaceService;

    @Mock
    private DataTypeService mockDataTypeService;

    @Mock
    private AnalysisService mockAnalysisService;

    @Mock
    private MemoryService mockMemoryService;

    @Mock
    private CommentService mockCommentService;

    @Mock
    private ProgramService mockProgramService;

    @Mock
    private SearchService mockSearchService;

    @Mock
    private VariableService mockVariableService;

    @Mock
    private HttpContext mockHttpContext;

    private ApiHandlerRegistry registry;

    @BeforeEach
    @SuppressWarnings("unused")
    void setUp() {
        registry = new ApiHandlerRegistry(
            mockServerManager,
            mockFunctionService,
            mockNamespaceService,
            mockDataTypeService,
            mockAnalysisService,
            mockCommentService,
            mockMemoryService,
            mockProgramService,
            mockSearchService,
            mockVariableService
        );
    }

    @Test
    void testConstructor_AcceptsParameters() {
        assertNotNull(registry);

        ApiHandlerRegistry testRegistry = new ApiHandlerRegistry(
            mockServerManager,
            mockFunctionService,
            mockNamespaceService,
            mockDataTypeService,
            mockAnalysisService,
            mockCommentService,
            mockMemoryService,
            mockProgramService,
            mockSearchService,
            mockVariableService
        );
        assertNotNull(testRegistry);
    }

    @Test
    void testRegisterAllEndpoints() {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        // Function endpoints
        verify(mockHttpServer).createContext(eq("/list_functions"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_function_code"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/rename_functions"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_function_by_address"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_current_address"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_current_function"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/search_functions_by_name"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_function_prototype"), any(HttpHandler.class));

        // Namespace endpoints
        verify(mockHttpServer).createContext(eq("/list_symbols"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_symbol_address"), any(HttpHandler.class));

        // DataType endpoints
        verify(mockHttpServer).createContext(eq("/list_data_types"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_data_type"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/update_structure"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/update_enum"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/create_structure"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/add_structure_field"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/create_enum"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/add_enum_value"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/find_data_type_usage"), any(HttpHandler.class));

        // Program endpoints
        verify(mockHttpServer).createContext(eq("/get_program_info"), any(HttpHandler.class));

        // Analysis endpoints
        verify(mockHttpServer).createContext(eq("/list_references"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/analyze_control_flow"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/analyze_data_flow"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_call_graph"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_references_from"), any(HttpHandler.class));

        // Memory endpoints
        verify(mockHttpServer).createContext(eq("/get_memory_layout"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_data_items"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/rename_data"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_address_data_type"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/read_memory"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_memory_permissions"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_address_data_type"), any(HttpHandler.class));

        // Comment endpoints
        verify(mockHttpServer).createContext(eq("/get_comment"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_comment"), any(HttpHandler.class));

        // Search endpoints
        verify(mockHttpServer).createContext(eq("/search_memory"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/search_disassembly"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/search_decompiled"), any(HttpHandler.class));

        // Variable endpoints
        verify(mockHttpServer).createContext(eq("/rename_variables"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/split_variable"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_variable_types"), any(HttpHandler.class));

        // MCP tools metadata endpoint
        verify(mockHttpServer).createContext(eq("/mcp/tools"), any(HttpHandler.class));
    }

    @Test
    void testRegisterAllEndpoints_HandlesNullServer() {
        when(mockServerManager.isServerRunning()).thenReturn(false);

        assertDoesNotThrow(() -> registry.registerAllEndpoints());

        verify(mockServerManager).isServerRunning();
        verify(mockServerManager, never()).getServer();
    }

    @Test
    void testExtractJsonString() {
        String json = """
            {"function_name": "main", "renames": {"a": "b"}}""";
        assertEquals("main", ApiHandlerRegistry.extractJsonString(json, "function_name"));
        assertNull(ApiHandlerRegistry.extractJsonString(json, "nonexistent"));
    }

    @Test
    void testExtractJsonObject() {
        String json = """
            {"function_name": "main", "renames": {"local_10": "buf", "local_14": "size"}}""";
        Map<String, String> result = ApiHandlerRegistry.extractJsonObject(json, "renames");
        assertEquals(2, result.size());
        assertEquals("buf", result.get("local_10"));
        assertEquals("size", result.get("local_14"));
    }

    @Test
    void testExtractJsonObject_Empty() {
        String json = """
            {"function_name": "main", "renames": {}}""";
        Map<String, String> result = ApiHandlerRegistry.extractJsonObject(json, "renames");
        assertEquals(0, result.size());
    }

    @Test
    void testExtractJsonArrayOfPairs() {
        String json = """
            {"name": "MY_STRUCT", "fields": [["x", "int"], ["y", "int"], ["name", "char[32]"]]}""";
        var result = ApiHandlerRegistry.extractJsonArrayOfPairs(json, "fields");
        assertNotNull(result);
        assertEquals(3, result.size());
        assertEquals("x", result.get(0)[0]);
        assertEquals("int", result.get(0)[1]);
        assertEquals("name", result.get(2)[0]);
        assertEquals("char[32]", result.get(2)[1]);
    }

    @Test
    void testExtractJsonArrayOfPairs_Empty() {
        String json = """
            {"name": "MY_STRUCT", "fields": []}""";
        var result = ApiHandlerRegistry.extractJsonArrayOfPairs(json, "fields");
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    void testExtractJsonArrayOfPairs_Missing() {
        String json = """
            {"name": "MY_STRUCT"}""";
        var result = ApiHandlerRegistry.extractJsonArrayOfPairs(json, "fields");
        assertNull(result);
    }

    @Test
    void testExtractJsonString_EscapedQuotes() {
        String json = """
            {"prototype": "int func(char *msg, \\"hello\\")"}""";
        assertEquals("int func(char *msg, \"hello\")", ApiHandlerRegistry.extractJsonString(json, "prototype"));
    }

    @Test
    void testExtractJsonString_EscapedBackslash() {
        String json = """
            {"path": "C:\\\\Users\\\\test"}""";
        assertEquals("C:\\Users\\test", ApiHandlerRegistry.extractJsonString(json, "path"));
    }

    @Test
    void testExtractJsonObject_EscapedQuotes() {
        String json = """
            {"renames": {"local_10": "msg_\\"hello\\""}}""";
        Map<String, String> result = ApiHandlerRegistry.extractJsonObject(json, "renames");
        assertEquals(1, result.size());
        assertEquals("msg_\"hello\"", result.get("local_10"));
    }

    @Test
    void testExtractJsonInt() {
        String json = """
            {"name": "MyStruct", "size": 64, "new_name": "Renamed"}""";
        assertEquals(64, ApiHandlerRegistry.extractJsonInt(json, "size"));
        assertNull(ApiHandlerRegistry.extractJsonInt(json, "nonexistent"));
        assertNull(ApiHandlerRegistry.extractJsonInt(json, "name"));
    }

    @Test
    void testExtractJsonInt_QuotedNumber() {
        String json = """
            {"name": "MyStruct", "size": "32"}""";
        assertEquals(32, ApiHandlerRegistry.extractJsonInt(json, "size"));
    }

    @Test
    void testExtractJsonLongObject() {
        String json = """
            {"name": "MY_FLAGS", "values": {"FLAG_READ": 1, "FLAG_WRITE": 2, "FLAG_EXEC": 4}}""";
        var result = ApiHandlerRegistry.extractJsonLongObject(json, "values");
        assertNotNull(result);
        assertEquals(3, result.size());
        assertEquals(1L, result.get("FLAG_READ"));
        assertEquals(2L, result.get("FLAG_WRITE"));
        assertEquals(4L, result.get("FLAG_EXEC"));
    }

    @Test
    void testExtractJsonLongObject_Empty() {
        String json = """
            {"name": "MY_FLAGS", "values": {}}""";
        var result = ApiHandlerRegistry.extractJsonLongObject(json, "values");
        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    void testExtractJsonLongObject_Missing() {
        String json = """
            {"name": "MY_FLAGS"}""";
        var result = ApiHandlerRegistry.extractJsonLongObject(json, "values");
        assertTrue(result.isEmpty());
    }

    @Test
    void testEndpointCount() {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        // 40 tool endpoints + 1 /mcp/tools metadata endpoint = 41
        verify(mockHttpServer, times(41)).createContext(anyString(), any(HttpHandler.class));
    }

    @Test
    void testToolDefsPopulated() {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        // Should have 40 tool definitions
        assertEquals(40, registry.getToolDefs().size());
    }

    @Test
    void testToolNamesAreSnakeCase() {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        for (ToolDef def : registry.getToolDefs()) {
            // Verify all tool names are snake_case (no uppercase letters)
            assertEquals(def.getName(), def.getName().toLowerCase(),
                "Tool name should be snake_case: " + def.getName());
        }
    }

    @Test
    void testAllToolDefsHaveDescriptions() {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        for (ToolDef def : registry.getToolDefs()) {
            assertNotNull(def.getDescription(),
                "Tool should have a description: " + def.getName());
            assert !def.getDescription().isBlank() :
                "Tool description should not be blank: " + def.getName();
        }
    }

    @Test
    void testAllToolDefsHaveValidInputSchemas() {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        for (ToolDef def : registry.getToolDefs()) {
            String schema = def.toInputSchemaJson();
            assertNotNull(schema, "Tool should have input schema: " + def.getName());
            assert schema.contains("\"type\":\"object\"") :
                "Input schema should be an object type: " + def.getName();
        }
    }

    @Test
    void testToolJsonContainsRequiredFields() {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        for (ToolDef def : registry.getToolDefs()) {
            String json = def.toToolJson();
            assert json.contains("\"name\"") : "Tool JSON should contain name: " + def.getName();
            assert json.contains("\"description\"") : "Tool JSON should contain description: " + def.getName();
            assert json.contains("\"inputSchema\"") : "Tool JSON should contain inputSchema: " + def.getName();
            assert json.contains("\"method\"") : "Tool JSON should contain method: " + def.getName();
        }
    }

    @Test
    void testPostToolsHaveCorrectMethod() {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        // These tools should be POST
        var postTools = java.util.Set.of(
            "rename_functions", "set_function_prototype",
            "rename_data", "set_address_data_type",
            "set_comment",
            "rename_variables", "split_variable", "set_variable_types",
            "create_structure", "add_structure_field", "update_structure",
            "create_enum", "add_enum_value", "update_enum"
        );

        for (ToolDef def : registry.getToolDefs()) {
            String json = def.toToolJson();
            if (postTools.contains(def.getName())) {
                assert json.contains("\"method\":\"POST\"") :
                    def.getName() + " should be POST";
            } else {
                assert json.contains("\"method\":\"GET\"") :
                    def.getName() + " should be GET";
            }
        }
    }

    @Test
    @DisplayName("/mcp/tools endpoint returns valid JSON array with all 40 tools")
    void testMcpToolsEndpoint_ReturnsAllTools() throws Exception {
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(com.sun.net.httpserver.HttpHandler.class)))
            .thenReturn(mockHttpContext);

        ArgumentCaptor<com.sun.net.httpserver.HttpHandler> handlerCaptor =
            ArgumentCaptor.forClass(com.sun.net.httpserver.HttpHandler.class);

        registry.registerAllEndpoints();

        verify(mockHttpServer).createContext(eq("/mcp/tools"), handlerCaptor.capture());
        com.sun.net.httpserver.HttpHandler handler = handlerCaptor.getValue();

        // Create a mock exchange for the /mcp/tools GET request
        HttpExchange mockExchange = org.mockito.Mockito.mock(HttpExchange.class);
        Headers mockHeaders = org.mockito.Mockito.mock(Headers.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockExchange.getRequestURI()).thenReturn(URI.create("/mcp/tools"));
        when(mockExchange.getRequestMethod()).thenReturn("GET");
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);

        handler.handle(mockExchange);

        String jsonOutput = outputStream.toString();

        // Verify it's a JSON array
        assertTrue(jsonOutput.startsWith("["), "Response should be a JSON array");
        assertTrue(jsonOutput.endsWith("]"), "Response should end with ]");

        // Verify all 40 tools are present by checking for each tool name
        for (ToolDef def : registry.getToolDefs()) {
            assertTrue(jsonOutput.contains("\"name\":\"" + def.getName() + "\""),
                "JSON should contain tool: " + def.getName());
        }

        // Verify essential fields exist for each tool entry
        assertTrue(jsonOutput.contains("\"description\""), "Should contain descriptions");
        assertTrue(jsonOutput.contains("\"inputSchema\""), "Should contain input schemas");
        assertTrue(jsonOutput.contains("\"method\""), "Should contain method indicators");

        // Verify the response was sent with 200 status and JSON content type
        verify(mockExchange).sendResponseHeaders(eq(200), any(long.class));
        verify(mockHeaders).set("Content-Type", "application/json; charset=utf-8");
    }
}
