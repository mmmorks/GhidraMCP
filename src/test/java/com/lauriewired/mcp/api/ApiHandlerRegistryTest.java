package com.lauriewired.mcp.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

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
        // Test that constructor accepts all required parameters
        assertNotNull(registry);
        
        // Verify the registry was created successfully
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
        // Setup mock to return the HTTP server
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        // Call the method
        registry.registerAllEndpoints();

        // Verify that all expected endpoints were registered
        // Function endpoints (consolidated)
        verify(mockHttpServer).createContext(eq("/list_functions"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_function_code"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/rename_function"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_function_by_address"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_current_address"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_current_function"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/search_functions_by_name"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_function_prototype"), any(HttpHandler.class));

        // Namespace endpoints (only symbols and symbol address remain)
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
    }

    @Test
    void testRegisterAllEndpoints_HandlesNullServer() {
        // Setup mock to return false for isServerRunning
        when(mockServerManager.isServerRunning()).thenReturn(false);

        // Should not throw, but handle gracefully
        assertDoesNotThrow(() -> registry.registerAllEndpoints());
        
        // Verify isServerRunning was called but getServer was not
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
    void testFindUnescapedQuote_SimpleQuote() {
        assertEquals(5, ApiHandlerRegistry.findUnescapedQuote("hello\"world", 0));
    }

    @Test
    void testFindUnescapedQuote_EscapedQuote() {
        // In the string: hello\"world" — the first quote is escaped, the second is not
        String s = "hello\\\"world\"";
        assertEquals(12, ApiHandlerRegistry.findUnescapedQuote(s, 0));
    }

    @Test
    void testFindUnescapedQuote_DoubleBackslashThenQuote() {
        // \\\\" — two backslashes then a quote: quote is NOT escaped
        String s = "hello\\\\\"world";
        assertEquals(7, ApiHandlerRegistry.findUnescapedQuote(s, 0));
    }

    @Test
    void testUnescapeJsonString_AllEscapes() {
        assertEquals("a\"b\\c\nd", ApiHandlerRegistry.unescapeJsonString("a\\\"b\\\\c\\nd"));
    }

    @Test
    void testUnescapeJsonString_Null() {
        assertNull(ApiHandlerRegistry.unescapeJsonString(null));
    }

    @Test
    void testUnescapeJsonString_NoEscapes() {
        assertEquals("hello", ApiHandlerRegistry.unescapeJsonString("hello"));
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
        assertNull(result);
    }

    @Test
    void testEndpointCount() {
        // Setup mock to return the HTTP server
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        // Verify the expected number of endpoints were registered
        // 40 endpoints total (was 44: +1 get_program_info, -3 call-graph consolidated to 1, -5 comment consolidated to 2)
        verify(mockHttpServer, times(40)).createContext(anyString(), any(HttpHandler.class));
    }
}